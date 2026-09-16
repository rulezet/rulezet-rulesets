rule TTP_XOR_QUAD_CurrentVersionRun_8948 {
  strings:
    $key_8948 = { da 27 [2] fe 29 [2] d5 05 [2] fb 27 [2] ef 3c [2] e0 26 [2] fe 3b [2] fc 3a [2] e7 3c [2] fb 3b [2] e7 14 }

  condition:
    any of them
}