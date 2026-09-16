rule TTP_XOR_QUAD_CurrentVersionRun_8906 {
  strings:
    $key_8906 = { da 69 [2] fe 67 [2] d5 4b [2] fb 69 [2] ef 72 [2] e0 68 [2] fe 75 [2] fc 74 [2] e7 72 [2] fb 75 [2] e7 5a }

  condition:
    any of them
}