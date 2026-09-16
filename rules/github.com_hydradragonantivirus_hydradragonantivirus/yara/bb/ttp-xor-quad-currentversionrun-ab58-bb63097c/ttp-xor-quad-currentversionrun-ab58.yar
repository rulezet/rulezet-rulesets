rule TTP_XOR_QUAD_CurrentVersionRun_ab58 {
  strings:
    $key_ab58 = { f8 37 [2] dc 39 [2] f7 15 [2] d9 37 [2] cd 2c [2] c2 36 [2] dc 2b [2] de 2a [2] c5 2c [2] d9 2b [2] c5 04 }

  condition:
    any of them
}