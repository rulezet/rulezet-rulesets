rule TTP_XOR_QUAD_CurrentVersionRun_a552 {
  strings:
    $key_a552 = { f6 3d [2] d2 33 [2] f9 1f [2] d7 3d [2] c3 26 [2] cc 3c [2] d2 21 [2] d0 20 [2] cb 26 [2] d7 21 [2] cb 0e }

  condition:
    any of them
}