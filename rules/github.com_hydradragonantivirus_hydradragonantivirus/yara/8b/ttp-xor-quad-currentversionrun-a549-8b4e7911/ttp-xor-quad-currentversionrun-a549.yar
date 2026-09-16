rule TTP_XOR_QUAD_CurrentVersionRun_a549 {
  strings:
    $key_a549 = { f6 26 [2] d2 28 [2] f9 04 [2] d7 26 [2] c3 3d [2] cc 27 [2] d2 3a [2] d0 3b [2] cb 3d [2] d7 3a [2] cb 15 }

  condition:
    any of them
}