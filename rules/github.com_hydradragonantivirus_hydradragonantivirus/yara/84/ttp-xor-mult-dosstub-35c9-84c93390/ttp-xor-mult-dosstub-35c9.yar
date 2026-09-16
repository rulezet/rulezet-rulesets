rule TTP_XOR_MULT_DOSStub_35c9 {
  strings:
    $key_35c9 = { 61 a1 [2] 15 b9 [2] 52 bb [2] 15 aa [2] 5b a6 [2] 57 ac [2] 40 a7 [2] 5b e9 [2] 66 }

  condition:
    any of them
}