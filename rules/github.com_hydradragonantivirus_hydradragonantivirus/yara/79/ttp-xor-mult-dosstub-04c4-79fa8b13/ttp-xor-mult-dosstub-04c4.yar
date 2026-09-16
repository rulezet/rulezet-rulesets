rule TTP_XOR_MULT_DOSStub_04c4 {
  strings:
    $key_04c4 = { 50 ac [2] 24 b4 [2] 63 b6 [2] 24 a7 [2] 6a ab [2] 66 a1 [2] 71 aa [2] 6a e4 [2] 57 }

  condition:
    any of them
}