rule TTP_XOR_QUAD_CurrentVersionRun_8cab {
  strings:
    $key_8cab = { df c4 [2] fb ca [2] d0 e6 [2] fe c4 [2] ea df [2] e5 c5 [2] fb d8 [2] f9 d9 [2] e2 df [2] fe d8 [2] e2 f7 }

  condition:
    any of them
}