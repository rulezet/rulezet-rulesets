rule TTP_XOR_QUAD_CurrentVersionRun_896e {
  strings:
    $key_896e = { da 01 [2] fe 0f [2] d5 23 [2] fb 01 [2] ef 1a [2] e0 00 [2] fe 1d [2] fc 1c [2] e7 1a [2] fb 1d [2] e7 32 }

  condition:
    any of them
}