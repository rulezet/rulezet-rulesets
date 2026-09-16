rule TTP_XOR_QUAD_CurrentVersionRun_abbe {
  strings:
    $key_abbe = { f8 d1 [2] dc df [2] f7 f3 [2] d9 d1 [2] cd ca [2] c2 d0 [2] dc cd [2] de cc [2] c5 ca [2] d9 cd [2] c5 e2 }

  condition:
    any of them
}