rule TTP_XOR_QUAD_CurrentVersionRun_d5aa {
  strings:
    $key_d5aa = { 86 c5 [2] a2 cb [2] 89 e7 [2] a7 c5 [2] b3 de [2] bc c4 [2] a2 d9 [2] a0 d8 [2] bb de [2] a7 d9 [2] bb f6 }

  condition:
    any of them
}