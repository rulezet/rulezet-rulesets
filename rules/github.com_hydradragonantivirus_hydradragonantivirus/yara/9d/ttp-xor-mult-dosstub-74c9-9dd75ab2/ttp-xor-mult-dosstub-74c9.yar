rule TTP_XOR_MULT_DOSStub_74c9 {
  strings:
    $key_74c9 = { 20 a1 [2] 54 b9 [2] 13 bb [2] 54 aa [2] 1a a6 [2] 16 ac [2] 01 a7 [2] 1a e9 [2] 27 }

  condition:
    any of them
}