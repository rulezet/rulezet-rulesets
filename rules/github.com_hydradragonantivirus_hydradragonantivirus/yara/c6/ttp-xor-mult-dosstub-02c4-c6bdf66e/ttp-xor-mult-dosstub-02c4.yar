rule TTP_XOR_MULT_DOSStub_02c4 {
  strings:
    $key_02c4 = { 56 ac [2] 22 b4 [2] 65 b6 [2] 22 a7 [2] 6c ab [2] 60 a1 [2] 77 aa [2] 6c e4 [2] 51 }

  condition:
    any of them
}