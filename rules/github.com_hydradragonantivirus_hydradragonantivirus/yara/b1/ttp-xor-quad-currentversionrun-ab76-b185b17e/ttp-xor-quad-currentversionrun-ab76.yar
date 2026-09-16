rule TTP_XOR_QUAD_CurrentVersionRun_ab76 {
  strings:
    $key_ab76 = { f8 19 [2] dc 17 [2] f7 3b [2] d9 19 [2] cd 02 [2] c2 18 [2] dc 05 [2] de 04 [2] c5 02 [2] d9 05 [2] c5 2a }

  condition:
    any of them
}