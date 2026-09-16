rule TTP_XOR_QUAD_CurrentVersionRun_ab45 {
  strings:
    $key_ab45 = { f8 2a [2] dc 24 [2] f7 08 [2] d9 2a [2] cd 31 [2] c2 2b [2] dc 36 [2] de 37 [2] c5 31 [2] d9 36 [2] c5 19 }

  condition:
    any of them
}