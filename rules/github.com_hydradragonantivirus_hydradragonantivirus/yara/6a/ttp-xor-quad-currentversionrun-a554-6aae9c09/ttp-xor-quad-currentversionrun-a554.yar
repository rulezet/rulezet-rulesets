rule TTP_XOR_QUAD_CurrentVersionRun_a554 {
  strings:
    $key_a554 = { f6 3b [2] d2 35 [2] f9 19 [2] d7 3b [2] c3 20 [2] cc 3a [2] d2 27 [2] d0 26 [2] cb 20 [2] d7 27 [2] cb 08 }

  condition:
    any of them
}