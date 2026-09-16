rule TTP_XOR_QUAD_CurrentVersionRun_bdaa {
  strings:
    $key_bdaa = { ee c5 [2] ca cb [2] e1 e7 [2] cf c5 [2] db de [2] d4 c4 [2] ca d9 [2] c8 d8 [2] d3 de [2] cf d9 [2] d3 f6 }

  condition:
    any of them
}