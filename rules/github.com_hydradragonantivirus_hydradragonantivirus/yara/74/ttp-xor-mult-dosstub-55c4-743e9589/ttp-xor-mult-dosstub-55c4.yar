rule TTP_XOR_MULT_DOSStub_55c4 {
  strings:
    $key_55c4 = { 01 ac [2] 75 b4 [2] 32 b6 [2] 75 a7 [2] 3b ab [2] 37 a1 [2] 20 aa [2] 3b e4 [2] 06 }

  condition:
    any of them
}