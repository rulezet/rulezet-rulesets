rule TTP_XOR_QUAD_CurrentVersionRun_8937 {
  strings:
    $key_8937 = { da 58 [2] fe 56 [2] d5 7a [2] fb 58 [2] ef 43 [2] e0 59 [2] fe 44 [2] fc 45 [2] e7 43 [2] fb 44 [2] e7 6b }

  condition:
    any of them
}