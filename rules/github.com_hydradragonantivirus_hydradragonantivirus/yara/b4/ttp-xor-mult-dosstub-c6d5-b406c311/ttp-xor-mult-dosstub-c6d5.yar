rule TTP_XOR_MULT_DOSStub_c6d5 {
  strings:
    $key_c6d5 = { 92 bd [2] e6 a5 [2] a1 a7 [2] e6 b6 [2] a8 ba [2] a4 b0 [2] b3 bb [2] a8 f5 [2] 95 }

  condition:
    any of them
}