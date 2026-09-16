rule TTP_XOR_QUAD_CurrentVersionRun_89eb {
  strings:
    $key_89eb = { da 84 [2] fe 8a [2] d5 a6 [2] fb 84 [2] ef 9f [2] e0 85 [2] fe 98 [2] fc 99 [2] e7 9f [2] fb 98 [2] e7 b7 }

  condition:
    any of them
}