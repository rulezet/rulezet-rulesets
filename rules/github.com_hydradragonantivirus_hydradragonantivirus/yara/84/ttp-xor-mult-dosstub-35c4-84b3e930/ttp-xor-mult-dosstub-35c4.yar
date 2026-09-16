rule TTP_XOR_MULT_DOSStub_35c4 {
  strings:
    $key_35c4 = { 61 ac [2] 15 b4 [2] 52 b6 [2] 15 a7 [2] 5b ab [2] 57 a1 [2] 40 aa [2] 5b e4 [2] 66 }

  condition:
    any of them
}