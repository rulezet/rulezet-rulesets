rule TTP_XOR_QUAD_CurrentVersionRun_dfaa {
  strings:
    $key_dfaa = { 8c c5 [2] a8 cb [2] 83 e7 [2] ad c5 [2] b9 de [2] b6 c4 [2] a8 d9 [2] aa d8 [2] b1 de [2] ad d9 [2] b1 f6 }

  condition:
    any of them
}