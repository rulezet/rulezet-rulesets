rule TTP_XOR_QUAD_CurrentVersionRun_8943 {
  strings:
    $key_8943 = { da 2c [2] fe 22 [2] d5 0e [2] fb 2c [2] ef 37 [2] e0 2d [2] fe 30 [2] fc 31 [2] e7 37 [2] fb 30 [2] e7 1f }

  condition:
    any of them
}