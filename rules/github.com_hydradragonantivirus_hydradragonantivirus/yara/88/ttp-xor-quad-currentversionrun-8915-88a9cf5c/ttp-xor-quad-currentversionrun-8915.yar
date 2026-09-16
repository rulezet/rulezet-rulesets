rule TTP_XOR_QUAD_CurrentVersionRun_8915 {
  strings:
    $key_8915 = { da 7a [2] fe 74 [2] d5 58 [2] fb 7a [2] ef 61 [2] e0 7b [2] fe 66 [2] fc 67 [2] e7 61 [2] fb 66 [2] e7 49 }

  condition:
    any of them
}