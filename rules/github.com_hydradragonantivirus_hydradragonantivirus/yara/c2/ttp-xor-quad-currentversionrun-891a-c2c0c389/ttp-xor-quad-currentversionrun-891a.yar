rule TTP_XOR_QUAD_CurrentVersionRun_891a {
  strings:
    $key_891a = { da 75 [2] fe 7b [2] d5 57 [2] fb 75 [2] ef 6e [2] e0 74 [2] fe 69 [2] fc 68 [2] e7 6e [2] fb 69 [2] e7 46 }

  condition:
    any of them
}