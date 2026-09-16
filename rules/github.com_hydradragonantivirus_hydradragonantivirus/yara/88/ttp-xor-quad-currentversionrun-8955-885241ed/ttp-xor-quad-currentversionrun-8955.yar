rule TTP_XOR_QUAD_CurrentVersionRun_8955 {
  strings:
    $key_8955 = { da 3a [2] fe 34 [2] d5 18 [2] fb 3a [2] ef 21 [2] e0 3b [2] fe 26 [2] fc 27 [2] e7 21 [2] fb 26 [2] e7 09 }

  condition:
    any of them
}