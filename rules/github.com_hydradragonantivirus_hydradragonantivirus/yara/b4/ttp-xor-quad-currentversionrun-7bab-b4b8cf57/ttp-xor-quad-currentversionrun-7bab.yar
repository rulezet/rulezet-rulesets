rule TTP_XOR_QUAD_CurrentVersionRun_7bab {
  strings:
    $key_7bab = { 28 c4 [2] 0c ca [2] 27 e6 [2] 09 c4 [2] 1d df [2] 12 c5 [2] 0c d8 [2] 0e d9 [2] 15 df [2] 09 d8 [2] 15 f7 }

  condition:
    any of them
}