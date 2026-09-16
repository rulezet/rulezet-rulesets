rule TTP_XOR_MULT_DOSStub_45c4 {
  strings:
    $key_45c4 = { 11 ac [2] 65 b4 [2] 22 b6 [2] 65 a7 [2] 2b ab [2] 27 a1 [2] 30 aa [2] 2b e4 [2] 16 }

  condition:
    any of them
}