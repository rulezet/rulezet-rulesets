rule TTP_XOR_QUAD_CurrentVersionRun_c4aa {
  strings:
    $key_c4aa = { 97 c5 [2] b3 cb [2] 98 e7 [2] b6 c5 [2] a2 de [2] ad c4 [2] b3 d9 [2] b1 d8 [2] aa de [2] b6 d9 [2] aa f6 }

  condition:
    any of them
}