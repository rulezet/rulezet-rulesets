rule TTP_XOR_QUAD_CurrentVersionRun_894a {
  strings:
    $key_894a = { da 25 [2] fe 2b [2] d5 07 [2] fb 25 [2] ef 3e [2] e0 24 [2] fe 39 [2] fc 38 [2] e7 3e [2] fb 39 [2] e7 16 }

  condition:
    any of them
}