rule TTP_XOR_QUAD_CurrentVersionRun_89ea {
  strings:
    $key_89ea = { da 85 [2] fe 8b [2] d5 a7 [2] fb 85 [2] ef 9e [2] e0 84 [2] fe 99 [2] fc 98 [2] e7 9e [2] fb 99 [2] e7 b6 }

  condition:
    any of them
}