rule TTP_XOR_QUAD_CurrentVersionRun_a558 {
  strings:
    $key_a558 = { f6 37 [2] d2 39 [2] f9 15 [2] d7 37 [2] c3 2c [2] cc 36 [2] d2 2b [2] d0 2a [2] cb 2c [2] d7 2b [2] cb 04 }

  condition:
    any of them
}