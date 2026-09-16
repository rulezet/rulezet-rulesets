rule TTP_XOR_MULT_DOSStub_02c9 {
  strings:
    $key_02c9 = { 56 a1 [2] 22 b9 [2] 65 bb [2] 22 aa [2] 6c a6 [2] 60 ac [2] 77 a7 [2] 6c e9 [2] 51 }

  condition:
    any of them
}