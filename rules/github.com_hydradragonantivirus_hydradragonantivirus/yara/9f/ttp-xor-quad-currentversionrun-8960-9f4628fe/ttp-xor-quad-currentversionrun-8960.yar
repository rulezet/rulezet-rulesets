rule TTP_XOR_QUAD_CurrentVersionRun_8960 {
  strings:
    $key_8960 = { da 0f [2] fe 01 [2] d5 2d [2] fb 0f [2] ef 14 [2] e0 0e [2] fe 13 [2] fc 12 [2] e7 14 [2] fb 13 [2] e7 3c }

  condition:
    any of them
}