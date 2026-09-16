rule TTP_XOR_MULT_DOSStub_b5d5 {
  strings:
    $key_b5d5 = { e1 bd [2] 95 a5 [2] d2 a7 [2] 95 b6 [2] db ba [2] d7 b0 [2] c0 bb [2] db f5 [2] e6 }

  condition:
    any of them
}