rule TTP_XOR_QUAD_CurrentVersionRun_89ab {
  strings:
    $key_89ab = { da c4 [2] fe ca [2] d5 e6 [2] fb c4 [2] ef df [2] e0 c5 [2] fe d8 [2] fc d9 [2] e7 df [2] fb d8 [2] e7 f7 }

  condition:
    any of them
}