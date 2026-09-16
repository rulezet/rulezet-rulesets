rule TTP_XOR_QUAD_CurrentVersionRun_a273 {
  strings:
    $key_a273 = { f1 1c [2] d5 12 [2] fe 3e [2] d0 1c [2] c4 07 [2] cb 1d [2] d5 00 [2] d7 01 [2] cc 07 [2] d0 00 [2] cc 2f }

  condition:
    any of them
}