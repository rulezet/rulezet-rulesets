rule TTP_XOR_MULT_DOSStub_07c9 {
  strings:
    $key_07c9 = { 53 a1 [2] 27 b9 [2] 60 bb [2] 27 aa [2] 69 a6 [2] 65 ac [2] 72 a7 [2] 69 e9 [2] 54 }

  condition:
    any of them
}