rule TTP_XOR_MULT_DOSStub_52c9 {
  strings:
    $key_52c9 = { 06 a1 [2] 72 b9 [2] 35 bb [2] 72 aa [2] 3c a6 [2] 30 ac [2] 27 a7 [2] 3c e9 [2] 01 }

  condition:
    any of them
}