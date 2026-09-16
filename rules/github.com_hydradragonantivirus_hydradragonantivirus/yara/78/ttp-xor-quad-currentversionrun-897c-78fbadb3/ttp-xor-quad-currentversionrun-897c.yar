rule TTP_XOR_QUAD_CurrentVersionRun_897c {
  strings:
    $key_897c = { da 13 [2] fe 1d [2] d5 31 [2] fb 13 [2] ef 08 [2] e0 12 [2] fe 0f [2] fc 0e [2] e7 08 [2] fb 0f [2] e7 20 }

  condition:
    any of them
}