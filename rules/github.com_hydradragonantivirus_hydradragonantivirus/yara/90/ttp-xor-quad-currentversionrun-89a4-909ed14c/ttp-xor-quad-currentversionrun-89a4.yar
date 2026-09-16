rule TTP_XOR_QUAD_CurrentVersionRun_89a4 {
  strings:
    $key_89a4 = { da cb [2] fe c5 [2] d5 e9 [2] fb cb [2] ef d0 [2] e0 ca [2] fe d7 [2] fc d6 [2] e7 d0 [2] fb d7 [2] e7 f8 }

  condition:
    any of them
}