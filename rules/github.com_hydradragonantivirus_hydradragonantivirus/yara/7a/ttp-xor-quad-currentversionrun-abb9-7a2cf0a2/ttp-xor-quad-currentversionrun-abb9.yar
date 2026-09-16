rule TTP_XOR_QUAD_CurrentVersionRun_abb9 {
  strings:
    $key_abb9 = { f8 d6 [2] dc d8 [2] f7 f4 [2] d9 d6 [2] cd cd [2] c2 d7 [2] dc ca [2] de cb [2] c5 cd [2] d9 ca [2] c5 e5 }

  condition:
    any of them
}