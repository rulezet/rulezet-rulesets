rule TTP_XOR_QUAD_CurrentVersionRun_a54e {
  strings:
    $key_a54e = { f6 21 [2] d2 2f [2] f9 03 [2] d7 21 [2] c3 3a [2] cc 20 [2] d2 3d [2] d0 3c [2] cb 3a [2] d7 3d [2] cb 12 }

  condition:
    any of them
}