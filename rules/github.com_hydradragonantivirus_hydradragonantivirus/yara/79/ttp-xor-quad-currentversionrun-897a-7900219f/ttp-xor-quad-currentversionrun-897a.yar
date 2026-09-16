rule TTP_XOR_QUAD_CurrentVersionRun_897a {
  strings:
    $key_897a = { da 15 [2] fe 1b [2] d5 37 [2] fb 15 [2] ef 0e [2] e0 14 [2] fe 09 [2] fc 08 [2] e7 0e [2] fb 09 [2] e7 26 }

  condition:
    any of them
}