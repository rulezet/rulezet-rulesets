rule TTP_XOR_QUAD_CurrentVersionRun_8919 {
  strings:
    $key_8919 = { da 76 [2] fe 78 [2] d5 54 [2] fb 76 [2] ef 6d [2] e0 77 [2] fe 6a [2] fc 6b [2] e7 6d [2] fb 6a [2] e7 45 }

  condition:
    any of them
}