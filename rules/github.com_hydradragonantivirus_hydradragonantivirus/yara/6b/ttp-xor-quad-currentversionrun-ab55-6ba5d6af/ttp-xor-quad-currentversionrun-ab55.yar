rule TTP_XOR_QUAD_CurrentVersionRun_ab55 {
  strings:
    $key_ab55 = { f8 3a [2] dc 34 [2] f7 18 [2] d9 3a [2] cd 21 [2] c2 3b [2] dc 26 [2] de 27 [2] c5 21 [2] d9 26 [2] c5 09 }

  condition:
    any of them
}