rule TTP_XOR_MULT_DOSStub_36c9 {
  strings:
    $key_36c9 = { 62 a1 [2] 16 b9 [2] 51 bb [2] 16 aa [2] 58 a6 [2] 54 ac [2] 43 a7 [2] 58 e9 [2] 65 }

  condition:
    any of them
}