rule TTP_XOR_QUAD_CurrentVersionRun_c187 {
  strings:
    $key_c187 = { 92 e8 [2] b6 e6 [2] 9d ca [2] b3 e8 [2] a7 f3 [2] a8 e9 [2] b6 f4 [2] b4 f5 [2] af f3 [2] b3 f4 [2] af db }

  condition:
    any of them
}