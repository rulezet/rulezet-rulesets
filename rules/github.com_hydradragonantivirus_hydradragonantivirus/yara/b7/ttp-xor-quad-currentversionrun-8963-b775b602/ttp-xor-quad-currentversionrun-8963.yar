rule TTP_XOR_QUAD_CurrentVersionRun_8963 {
  strings:
    $key_8963 = { da 0c [2] fe 02 [2] d5 2e [2] fb 0c [2] ef 17 [2] e0 0d [2] fe 10 [2] fc 11 [2] e7 17 [2] fb 10 [2] e7 3f }

  condition:
    any of them
}