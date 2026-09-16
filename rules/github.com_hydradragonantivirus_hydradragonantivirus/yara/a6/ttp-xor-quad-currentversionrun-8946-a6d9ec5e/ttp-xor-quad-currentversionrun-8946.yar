rule TTP_XOR_QUAD_CurrentVersionRun_8946 {
  strings:
    $key_8946 = { da 29 [2] fe 27 [2] d5 0b [2] fb 29 [2] ef 32 [2] e0 28 [2] fe 35 [2] fc 34 [2] e7 32 [2] fb 35 [2] e7 1a }

  condition:
    any of them
}