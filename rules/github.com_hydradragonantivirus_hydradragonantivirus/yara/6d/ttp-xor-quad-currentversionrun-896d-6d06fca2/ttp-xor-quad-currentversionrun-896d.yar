rule TTP_XOR_QUAD_CurrentVersionRun_896d {
  strings:
    $key_896d = { da 02 [2] fe 0c [2] d5 20 [2] fb 02 [2] ef 19 [2] e0 03 [2] fe 1e [2] fc 1f [2] e7 19 [2] fb 1e [2] e7 31 }

  condition:
    any of them
}