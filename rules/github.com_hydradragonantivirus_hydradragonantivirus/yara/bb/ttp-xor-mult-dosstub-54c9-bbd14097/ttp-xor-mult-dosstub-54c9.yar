rule TTP_XOR_MULT_DOSStub_54c9 {
  strings:
    $key_54c9 = { 00 a1 [2] 74 b9 [2] 33 bb [2] 74 aa [2] 3a a6 [2] 36 ac [2] 21 a7 [2] 3a e9 [2] 07 }

  condition:
    any of them
}