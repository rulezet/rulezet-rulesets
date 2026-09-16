rule TTP_XOR_QUAD_CurrentVersionRun_896a {
  strings:
    $key_896a = { da 05 [2] fe 0b [2] d5 27 [2] fb 05 [2] ef 1e [2] e0 04 [2] fe 19 [2] fc 18 [2] e7 1e [2] fb 19 [2] e7 36 }

  condition:
    any of them
}