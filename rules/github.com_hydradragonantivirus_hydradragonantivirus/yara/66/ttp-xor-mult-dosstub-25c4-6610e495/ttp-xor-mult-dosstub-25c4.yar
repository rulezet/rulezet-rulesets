rule TTP_XOR_MULT_DOSStub_25c4 {
  strings:
    $key_25c4 = { 71 ac [2] 05 b4 [2] 42 b6 [2] 05 a7 [2] 4b ab [2] 47 a1 [2] 50 aa [2] 4b e4 [2] 76 }

  condition:
    any of them
}