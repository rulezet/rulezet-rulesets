rule TTP_XOR_QUAD_CurrentVersionRun_a24e {
  strings:
    $key_a24e = { f1 21 [2] d5 2f [2] fe 03 [2] d0 21 [2] c4 3a [2] cb 20 [2] d5 3d [2] d7 3c [2] cc 3a [2] d0 3d [2] cc 12 }

  condition:
    any of them
}