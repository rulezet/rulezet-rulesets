rule TTP_XOR_MULT_DOSStub_46c9 {
  strings:
    $key_46c9 = { 12 a1 [2] 66 b9 [2] 21 bb [2] 66 aa [2] 28 a6 [2] 24 ac [2] 33 a7 [2] 28 e9 [2] 15 }

  condition:
    any of them
}