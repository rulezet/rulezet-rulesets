rule TTP_XOR_QUAD_CurrentVersionRun_8959 {
  strings:
    $key_8959 = { da 36 [2] fe 38 [2] d5 14 [2] fb 36 [2] ef 2d [2] e0 37 [2] fe 2a [2] fc 2b [2] e7 2d [2] fb 2a [2] e7 05 }

  condition:
    any of them
}