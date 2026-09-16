rule TTP_XOR_QUAD_CurrentVersionRun_a272 {
  strings:
    $key_a272 = { f1 1d [2] d5 13 [2] fe 3f [2] d0 1d [2] c4 06 [2] cb 1c [2] d5 01 [2] d7 00 [2] cc 06 [2] d0 01 [2] cc 2e }

  condition:
    any of them
}