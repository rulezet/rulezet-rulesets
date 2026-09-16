rule TTP_XOR_QUAD_CurrentVersionRun_8fa5 {
  strings:
    $key_8fa5 = { dc ca [2] f8 c4 [2] d3 e8 [2] fd ca [2] e9 d1 [2] e6 cb [2] f8 d6 [2] fa d7 [2] e1 d1 [2] fd d6 [2] e1 f9 }

  condition:
    any of them
}