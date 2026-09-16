rule TTP_XOR_QUAD_CurrentVersionRun_8900 {
  strings:
    $key_8900 = { da 6f [2] fe 61 [2] d5 4d [2] fb 6f [2] ef 74 [2] e0 6e [2] fe 73 [2] fc 72 [2] e7 74 [2] fb 73 [2] e7 5c }

  condition:
    any of them
}