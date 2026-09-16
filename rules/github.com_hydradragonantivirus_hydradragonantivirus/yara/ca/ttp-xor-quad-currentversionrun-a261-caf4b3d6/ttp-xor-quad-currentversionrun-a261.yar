rule TTP_XOR_QUAD_CurrentVersionRun_a261 {
  strings:
    $key_a261 = { f1 0e [2] d5 00 [2] fe 2c [2] d0 0e [2] c4 15 [2] cb 0f [2] d5 12 [2] d7 13 [2] cc 15 [2] d0 12 [2] cc 3d }

  condition:
    any of them
}