rule TTP_XOR_QUAD_CurrentVersionRun_89f3 {
  strings:
    $key_89f3 = { da 9c [2] fe 92 [2] d5 be [2] fb 9c [2] ef 87 [2] e0 9d [2] fe 80 [2] fc 81 [2] e7 87 [2] fb 80 [2] e7 af }

  condition:
    any of them
}