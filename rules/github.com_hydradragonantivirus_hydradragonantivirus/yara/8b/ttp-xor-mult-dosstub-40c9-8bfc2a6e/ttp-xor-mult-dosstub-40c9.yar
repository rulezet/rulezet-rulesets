rule TTP_XOR_MULT_DOSStub_40c9 {
  strings:
    $key_40c9 = { 14 a1 [2] 60 b9 [2] 27 bb [2] 60 aa [2] 2e a6 [2] 22 ac [2] 35 a7 [2] 2e e9 [2] 13 }

  condition:
    any of them
}