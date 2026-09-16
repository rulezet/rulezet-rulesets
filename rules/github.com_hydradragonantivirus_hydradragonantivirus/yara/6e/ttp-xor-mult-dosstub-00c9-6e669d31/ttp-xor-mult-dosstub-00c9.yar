rule TTP_XOR_MULT_DOSStub_00c9 {
  strings:
    $key_00c9 = { 54 a1 [2] 20 b9 [2] 67 bb [2] 20 aa [2] 6e a6 [2] 62 ac [2] 75 a7 [2] 6e e9 [2] 53 }

  condition:
    any of them
}