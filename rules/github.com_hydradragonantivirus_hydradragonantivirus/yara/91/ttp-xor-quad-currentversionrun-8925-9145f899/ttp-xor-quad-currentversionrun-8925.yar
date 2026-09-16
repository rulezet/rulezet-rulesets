rule TTP_XOR_QUAD_CurrentVersionRun_8925 {
  strings:
    $key_8925 = { da 4a [2] fe 44 [2] d5 68 [2] fb 4a [2] ef 51 [2] e0 4b [2] fe 56 [2] fc 57 [2] e7 51 [2] fb 56 [2] e7 79 }

  condition:
    any of them
}