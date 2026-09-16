rule TTP_XOR_QUAD_CurrentVersionRun_8914 {
  strings:
    $key_8914 = { da 7b [2] fe 75 [2] d5 59 [2] fb 7b [2] ef 60 [2] e0 7a [2] fe 67 [2] fc 66 [2] e7 60 [2] fb 67 [2] e7 48 }

  condition:
    any of them
}