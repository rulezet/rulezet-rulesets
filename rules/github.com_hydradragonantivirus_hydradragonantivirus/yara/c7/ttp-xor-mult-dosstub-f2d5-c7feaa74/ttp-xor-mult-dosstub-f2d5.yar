rule TTP_XOR_MULT_DOSStub_f2d5 {
  strings:
    $key_f2d5 = { a6 bd [2] d2 a5 [2] 95 a7 [2] d2 b6 [2] 9c ba [2] 90 b0 [2] 87 bb [2] 9c f5 [2] a1 }

  condition:
    any of them
}