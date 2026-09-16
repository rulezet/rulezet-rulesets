rule TTP_XOR_QUAD_CurrentVersionRun_89fa {
  strings:
    $key_89fa = { da 95 [2] fe 9b [2] d5 b7 [2] fb 95 [2] ef 8e [2] e0 94 [2] fe 89 [2] fc 88 [2] e7 8e [2] fb 89 [2] e7 a6 }

  condition:
    any of them
}