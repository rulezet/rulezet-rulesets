rule TTP_XOR_MULT_DOSStub_45c9 {
  strings:
    $key_45c9 = { 11 a1 [2] 65 b9 [2] 22 bb [2] 65 aa [2] 2b a6 [2] 27 ac [2] 30 a7 [2] 2b e9 [2] 16 }

  condition:
    any of them
}