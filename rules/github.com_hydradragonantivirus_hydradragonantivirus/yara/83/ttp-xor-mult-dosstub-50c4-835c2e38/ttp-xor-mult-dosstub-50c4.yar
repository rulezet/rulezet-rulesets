rule TTP_XOR_MULT_DOSStub_50c4 {
  strings:
    $key_50c4 = { 04 ac [2] 70 b4 [2] 37 b6 [2] 70 a7 [2] 3e ab [2] 32 a1 [2] 25 aa [2] 3e e4 [2] 03 }

  condition:
    any of them
}