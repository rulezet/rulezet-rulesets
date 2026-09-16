rule TTP_XOR_QUAD_CurrentVersionRun_897d {
  strings:
    $key_897d = { da 12 [2] fe 1c [2] d5 30 [2] fb 12 [2] ef 09 [2] e0 13 [2] fe 0e [2] fc 0f [2] e7 09 [2] fb 0e [2] e7 21 }

  condition:
    any of them
}