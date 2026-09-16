rule TTP_XOR_QUAD_CurrentVersionRun_8931 {
  strings:
    $key_8931 = { da 5e [2] fe 50 [2] d5 7c [2] fb 5e [2] ef 45 [2] e0 5f [2] fe 42 [2] fc 43 [2] e7 45 [2] fb 42 [2] e7 6d }

  condition:
    any of them
}