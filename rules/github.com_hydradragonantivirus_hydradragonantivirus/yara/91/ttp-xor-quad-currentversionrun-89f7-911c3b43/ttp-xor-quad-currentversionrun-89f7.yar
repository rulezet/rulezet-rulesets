rule TTP_XOR_QUAD_CurrentVersionRun_89f7 {
  strings:
    $key_89f7 = { da 98 [2] fe 96 [2] d5 ba [2] fb 98 [2] ef 83 [2] e0 99 [2] fe 84 [2] fc 85 [2] e7 83 [2] fb 84 [2] e7 ab }

  condition:
    any of them
}