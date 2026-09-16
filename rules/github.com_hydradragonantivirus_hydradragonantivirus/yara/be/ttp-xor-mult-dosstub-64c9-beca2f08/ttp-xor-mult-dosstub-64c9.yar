rule TTP_XOR_MULT_DOSStub_64c9 {
  strings:
    $key_64c9 = { 30 a1 [2] 44 b9 [2] 03 bb [2] 44 aa [2] 0a a6 [2] 06 ac [2] 11 a7 [2] 0a e9 [2] 37 }

  condition:
    any of them
}