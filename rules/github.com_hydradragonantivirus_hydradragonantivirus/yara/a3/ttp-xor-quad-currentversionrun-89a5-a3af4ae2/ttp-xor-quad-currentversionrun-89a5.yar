rule TTP_XOR_QUAD_CurrentVersionRun_89a5 {
  strings:
    $key_89a5 = { da ca [2] fe c4 [2] d5 e8 [2] fb ca [2] ef d1 [2] e0 cb [2] fe d6 [2] fc d7 [2] e7 d1 [2] fb d6 [2] e7 f9 }

  condition:
    any of them
}