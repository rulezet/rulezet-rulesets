rule TTP_XOR_QUAD_CurrentVersionRun_894d {
  strings:
    $key_894d = { da 22 [2] fe 2c [2] d5 00 [2] fb 22 [2] ef 39 [2] e0 23 [2] fe 3e [2] fc 3f [2] e7 39 [2] fb 3e [2] e7 11 }

  condition:
    any of them
}