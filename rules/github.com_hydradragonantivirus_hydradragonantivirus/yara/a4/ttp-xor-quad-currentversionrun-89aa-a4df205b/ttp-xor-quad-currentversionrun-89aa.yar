rule TTP_XOR_QUAD_CurrentVersionRun_89aa {
  strings:
    $key_89aa = { da c5 [2] fe cb [2] d5 e7 [2] fb c5 [2] ef de [2] e0 c4 [2] fe d9 [2] fc d8 [2] e7 de [2] fb d9 [2] e7 f6 }

  condition:
    any of them
}