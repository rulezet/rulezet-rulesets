rule TTP_XOR_MULT_DOSStub_43d5 {
  strings:
    $key_43d5 = { 17 bd [2] 63 a5 [2] 24 a7 [2] 63 b6 [2] 2d ba [2] 21 b0 [2] 36 bb [2] 2d f5 [2] 10 }

  condition:
    any of them
}