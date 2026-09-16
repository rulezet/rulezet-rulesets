rule TTP_XOR_MULT_DOSStub_e0d5 {
  strings:
    $key_e0d5 = { b4 bd [2] c0 a5 [2] 87 a7 [2] c0 b6 [2] 8e ba [2] 82 b0 [2] 95 bb [2] 8e f5 [2] b3 }

  condition:
    any of them
}