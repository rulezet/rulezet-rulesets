rule TTP_XOR_MULT_DOSStub_03c9 {
  strings:
    $key_03c9 = { 57 a1 [2] 23 b9 [2] 64 bb [2] 23 aa [2] 6d a6 [2] 61 ac [2] 76 a7 [2] 6d e9 [2] 50 }

  condition:
    any of them
}