rule TTP_XOR_QUAD_CurrentVersionRun_89e9 {
  strings:
    $key_89e9 = { da 86 [2] fe 88 [2] d5 a4 [2] fb 86 [2] ef 9d [2] e0 87 [2] fe 9a [2] fc 9b [2] e7 9d [2] fb 9a [2] e7 b5 }

  condition:
    any of them
}