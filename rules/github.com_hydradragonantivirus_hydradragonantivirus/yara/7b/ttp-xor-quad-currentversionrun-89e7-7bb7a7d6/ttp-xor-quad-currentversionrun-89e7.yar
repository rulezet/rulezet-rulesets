rule TTP_XOR_QUAD_CurrentVersionRun_89e7 {
  strings:
    $key_89e7 = { da 88 [2] fe 86 [2] d5 aa [2] fb 88 [2] ef 93 [2] e0 89 [2] fe 94 [2] fc 95 [2] e7 93 [2] fb 94 [2] e7 bb }

  condition:
    any of them
}