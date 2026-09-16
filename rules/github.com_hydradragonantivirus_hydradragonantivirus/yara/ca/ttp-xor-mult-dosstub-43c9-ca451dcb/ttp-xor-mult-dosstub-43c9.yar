rule TTP_XOR_MULT_DOSStub_43c9 {
  strings:
    $key_43c9 = { 17 a1 [2] 63 b9 [2] 24 bb [2] 63 aa [2] 2d a6 [2] 21 ac [2] 36 a7 [2] 2d e9 [2] 10 }

  condition:
    any of them
}