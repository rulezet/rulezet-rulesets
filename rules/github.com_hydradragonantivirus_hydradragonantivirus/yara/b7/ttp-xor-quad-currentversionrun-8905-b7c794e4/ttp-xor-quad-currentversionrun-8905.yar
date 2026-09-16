rule TTP_XOR_QUAD_CurrentVersionRun_8905 {
  strings:
    $key_8905 = { da 6a [2] fe 64 [2] d5 48 [2] fb 6a [2] ef 71 [2] e0 6b [2] fe 76 [2] fc 77 [2] e7 71 [2] fb 76 [2] e7 59 }

  condition:
    any of them
}