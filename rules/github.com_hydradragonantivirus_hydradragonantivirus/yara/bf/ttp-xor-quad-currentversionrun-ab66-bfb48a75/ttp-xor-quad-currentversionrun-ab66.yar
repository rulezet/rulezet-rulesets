rule TTP_XOR_QUAD_CurrentVersionRun_ab66 {
  strings:
    $key_ab66 = { f8 09 [2] dc 07 [2] f7 2b [2] d9 09 [2] cd 12 [2] c2 08 [2] dc 15 [2] de 14 [2] c5 12 [2] d9 15 [2] c5 3a }

  condition:
    any of them
}