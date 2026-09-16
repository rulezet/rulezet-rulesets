rule TTP_XOR_QUAD_CurrentVersionRun_fbab {
  strings:
    $key_fbab = { a8 c4 [2] 8c ca [2] a7 e6 [2] 89 c4 [2] 9d df [2] 92 c5 [2] 8c d8 [2] 8e d9 [2] 95 df [2] 89 d8 [2] 95 f7 }

  condition:
    any of them
}