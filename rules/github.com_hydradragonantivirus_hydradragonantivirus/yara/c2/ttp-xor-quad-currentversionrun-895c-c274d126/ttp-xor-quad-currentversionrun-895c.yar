rule TTP_XOR_QUAD_CurrentVersionRun_895c {
  strings:
    $key_895c = { da 33 [2] fe 3d [2] d5 11 [2] fb 33 [2] ef 28 [2] e0 32 [2] fe 2f [2] fc 2e [2] e7 28 [2] fb 2f [2] e7 00 }

  condition:
    any of them
}