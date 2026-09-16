rule TTP_XOR_QUAD_CurrentVersionRun_a252 {
  strings:
    $key_a252 = { f1 3d [2] d5 33 [2] fe 1f [2] d0 3d [2] c4 26 [2] cb 3c [2] d5 21 [2] d7 20 [2] cc 26 [2] d0 21 [2] cc 0e }

  condition:
    any of them
}