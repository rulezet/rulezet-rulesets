rule TTP_XOR_MULT_DOSStub_41d5 {
  strings:
    $key_41d5 = { 15 bd [2] 61 a5 [2] 26 a7 [2] 61 b6 [2] 2f ba [2] 23 b0 [2] 34 bb [2] 2f f5 [2] 12 }

  condition:
    any of them
}