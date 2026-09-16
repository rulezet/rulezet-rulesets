rule TTP_XOR_QUAD_CurrentVersionRun_8fb8 {
  strings:
    $key_8fb8 = { dc d7 [2] f8 d9 [2] d3 f5 [2] fd d7 [2] e9 cc [2] e6 d6 [2] f8 cb [2] fa ca [2] e1 cc [2] fd cb [2] e1 e4 }

  condition:
    any of them
}