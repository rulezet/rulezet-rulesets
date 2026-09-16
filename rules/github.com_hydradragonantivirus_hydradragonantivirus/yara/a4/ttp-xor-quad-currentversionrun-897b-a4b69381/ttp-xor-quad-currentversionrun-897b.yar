rule TTP_XOR_QUAD_CurrentVersionRun_897b {
  strings:
    $key_897b = { da 14 [2] fe 1a [2] d5 36 [2] fb 14 [2] ef 0f [2] e0 15 [2] fe 08 [2] fc 09 [2] e7 0f [2] fb 08 [2] e7 27 }

  condition:
    any of them
}