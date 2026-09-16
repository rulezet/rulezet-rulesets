rule TTP_XOR_QUAD_CurrentVersionRun_895b {
  strings:
    $key_895b = { da 34 [2] fe 3a [2] d5 16 [2] fb 34 [2] ef 2f [2] e0 35 [2] fe 28 [2] fc 29 [2] e7 2f [2] fb 28 [2] e7 07 }

  condition:
    any of them
}