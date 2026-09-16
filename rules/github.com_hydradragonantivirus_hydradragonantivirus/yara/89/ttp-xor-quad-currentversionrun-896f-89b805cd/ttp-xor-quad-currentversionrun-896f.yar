rule TTP_XOR_QUAD_CurrentVersionRun_896f {
  strings:
    $key_896f = { da 00 [2] fe 0e [2] d5 22 [2] fb 00 [2] ef 1b [2] e0 01 [2] fe 1c [2] fc 1d [2] e7 1b [2] fb 1c [2] e7 33 }

  condition:
    any of them
}