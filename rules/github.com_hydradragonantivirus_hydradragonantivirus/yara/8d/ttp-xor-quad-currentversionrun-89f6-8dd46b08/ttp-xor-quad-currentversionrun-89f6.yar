rule TTP_XOR_QUAD_CurrentVersionRun_89f6 {
  strings:
    $key_89f6 = { da 99 [2] fe 97 [2] d5 bb [2] fb 99 [2] ef 82 [2] e0 98 [2] fe 85 [2] fc 84 [2] e7 82 [2] fb 85 [2] e7 aa }

  condition:
    any of them
}