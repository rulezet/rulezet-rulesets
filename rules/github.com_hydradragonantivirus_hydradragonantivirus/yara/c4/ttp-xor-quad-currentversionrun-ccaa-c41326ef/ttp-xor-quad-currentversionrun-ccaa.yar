rule TTP_XOR_QUAD_CurrentVersionRun_ccaa {
  strings:
    $key_ccaa = { 9f c5 [2] bb cb [2] 90 e7 [2] be c5 [2] aa de [2] a5 c4 [2] bb d9 [2] b9 d8 [2] a2 de [2] be d9 [2] a2 f6 }

  condition:
    any of them
}