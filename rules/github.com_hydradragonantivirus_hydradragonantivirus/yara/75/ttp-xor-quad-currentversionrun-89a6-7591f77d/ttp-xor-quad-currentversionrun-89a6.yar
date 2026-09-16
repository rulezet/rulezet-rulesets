rule TTP_XOR_QUAD_CurrentVersionRun_89a6 {
  strings:
    $key_89a6 = { da c9 [2] fe c7 [2] d5 eb [2] fb c9 [2] ef d2 [2] e0 c8 [2] fe d5 [2] fc d4 [2] e7 d2 [2] fb d5 [2] e7 fa }

  condition:
    any of them
}