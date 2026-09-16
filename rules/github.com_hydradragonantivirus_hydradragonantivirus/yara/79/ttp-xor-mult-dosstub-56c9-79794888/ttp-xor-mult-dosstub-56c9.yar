rule TTP_XOR_MULT_DOSStub_56c9 {
  strings:
    $key_56c9 = { 02 a1 [2] 76 b9 [2] 31 bb [2] 76 aa [2] 38 a6 [2] 34 ac [2] 23 a7 [2] 38 e9 [2] 05 }

  condition:
    any of them
}