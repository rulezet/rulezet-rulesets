rule TTP_XOR_QUAD_CurrentVersionRun_89be {
  strings:
    $key_89be = { da d1 [2] fe df [2] d5 f3 [2] fb d1 [2] ef ca [2] e0 d0 [2] fe cd [2] fc cc [2] e7 ca [2] fb cd [2] e7 e2 }

  condition:
    any of them
}