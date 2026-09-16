rule TTP_XOR_QUAD_CurrentVersionRun_89b7 {
  strings:
    $key_89b7 = { da d8 [2] fe d6 [2] d5 fa [2] fb d8 [2] ef c3 [2] e0 d9 [2] fe c4 [2] fc c5 [2] e7 c3 [2] fb c4 [2] e7 eb }

  condition:
    any of them
}