rule TTP_XOR_QUAD_CurrentVersionRun_891b {
  strings:
    $key_891b = { da 74 [2] fe 7a [2] d5 56 [2] fb 74 [2] ef 6f [2] e0 75 [2] fe 68 [2] fc 69 [2] e7 6f [2] fb 68 [2] e7 47 }

  condition:
    any of them
}