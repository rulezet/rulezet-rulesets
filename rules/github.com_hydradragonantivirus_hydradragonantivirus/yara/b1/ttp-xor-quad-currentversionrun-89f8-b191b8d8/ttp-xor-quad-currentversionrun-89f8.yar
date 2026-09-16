rule TTP_XOR_QUAD_CurrentVersionRun_89f8 {
  strings:
    $key_89f8 = { da 97 [2] fe 99 [2] d5 b5 [2] fb 97 [2] ef 8c [2] e0 96 [2] fe 8b [2] fc 8a [2] e7 8c [2] fb 8b [2] e7 a4 }

  condition:
    any of them
}