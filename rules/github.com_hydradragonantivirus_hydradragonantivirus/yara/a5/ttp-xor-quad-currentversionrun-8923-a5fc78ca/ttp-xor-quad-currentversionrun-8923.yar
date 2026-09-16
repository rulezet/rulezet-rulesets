rule TTP_XOR_QUAD_CurrentVersionRun_8923 {
  strings:
    $key_8923 = { da 4c [2] fe 42 [2] d5 6e [2] fb 4c [2] ef 57 [2] e0 4d [2] fe 50 [2] fc 51 [2] e7 57 [2] fb 50 [2] e7 7f }

  condition:
    any of them
}