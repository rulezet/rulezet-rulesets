rule TTP_XOR_QUAD_CurrentVersionRun_892d {
  strings:
    $key_892d = { da 42 [2] fe 4c [2] d5 60 [2] fb 42 [2] ef 59 [2] e0 43 [2] fe 5e [2] fc 5f [2] e7 59 [2] fb 5e [2] e7 71 }

  condition:
    any of them
}