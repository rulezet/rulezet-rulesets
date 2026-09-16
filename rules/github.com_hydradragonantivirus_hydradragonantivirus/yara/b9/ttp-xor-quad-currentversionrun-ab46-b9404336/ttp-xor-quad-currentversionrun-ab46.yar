rule TTP_XOR_QUAD_CurrentVersionRun_ab46 {
  strings:
    $key_ab46 = { f8 29 [2] dc 27 [2] f7 0b [2] d9 29 [2] cd 32 [2] c2 28 [2] dc 35 [2] de 34 [2] c5 32 [2] d9 35 [2] c5 1a }

  condition:
    any of them
}