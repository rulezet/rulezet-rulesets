rule TTP_XOR_QUAD_CurrentVersionRun_8967 {
  strings:
    $key_8967 = { da 08 [2] fe 06 [2] d5 2a [2] fb 08 [2] ef 13 [2] e0 09 [2] fe 14 [2] fc 15 [2] e7 13 [2] fb 14 [2] e7 3b }

  condition:
    any of them
}