rule TTP_XOR_QUAD_CurrentVersionRun_8941 {
  strings:
    $key_8941 = { da 2e [2] fe 20 [2] d5 0c [2] fb 2e [2] ef 35 [2] e0 2f [2] fe 32 [2] fc 33 [2] e7 35 [2] fb 32 [2] e7 1d }

  condition:
    any of them
}