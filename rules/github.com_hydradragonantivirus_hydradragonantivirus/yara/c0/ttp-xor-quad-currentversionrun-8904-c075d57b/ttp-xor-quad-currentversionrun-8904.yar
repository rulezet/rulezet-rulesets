rule TTP_XOR_QUAD_CurrentVersionRun_8904 {
  strings:
    $key_8904 = { da 6b [2] fe 65 [2] d5 49 [2] fb 6b [2] ef 70 [2] e0 6a [2] fe 77 [2] fc 76 [2] e7 70 [2] fb 77 [2] e7 58 }

  condition:
    any of them
}