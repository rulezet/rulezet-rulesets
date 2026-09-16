rule TTP_XOR_QUAD_CurrentVersionRun_abed {
  strings:
    $key_abed = { f8 82 [2] dc 8c [2] f7 a0 [2] d9 82 [2] cd 99 [2] c2 83 [2] dc 9e [2] de 9f [2] c5 99 [2] d9 9e [2] c5 b1 }

  condition:
    any of them
}