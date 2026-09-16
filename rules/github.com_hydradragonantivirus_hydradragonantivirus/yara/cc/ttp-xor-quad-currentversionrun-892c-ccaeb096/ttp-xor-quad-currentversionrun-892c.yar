rule TTP_XOR_QUAD_CurrentVersionRun_892c {
  strings:
    $key_892c = { da 43 [2] fe 4d [2] d5 61 [2] fb 43 [2] ef 58 [2] e0 42 [2] fe 5f [2] fc 5e [2] e7 58 [2] fb 5f [2] e7 70 }

  condition:
    any of them
}