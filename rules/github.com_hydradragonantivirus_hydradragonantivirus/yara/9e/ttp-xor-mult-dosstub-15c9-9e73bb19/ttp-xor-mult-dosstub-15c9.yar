rule TTP_XOR_MULT_DOSStub_15c9 {
  strings:
    $key_15c9 = { 41 a1 [2] 35 b9 [2] 72 bb [2] 35 aa [2] 7b a6 [2] 77 ac [2] 60 a7 [2] 7b e9 [2] 46 }

  condition:
    any of them
}