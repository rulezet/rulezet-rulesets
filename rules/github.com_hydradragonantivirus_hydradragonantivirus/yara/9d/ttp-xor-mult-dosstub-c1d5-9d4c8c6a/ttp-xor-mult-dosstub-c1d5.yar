rule TTP_XOR_MULT_DOSStub_c1d5 {
  strings:
    $key_c1d5 = { 95 bd [2] e1 a5 [2] a6 a7 [2] e1 b6 [2] af ba [2] a3 b0 [2] b4 bb [2] af f5 [2] 92 }

  condition:
    any of them
}