rule TTP_XOR_MULT_DOSStub_67c4 {
  strings:
    $key_67c4 = { 33 ac [2] 47 b4 [2] 00 b6 [2] 47 a7 [2] 09 ab [2] 05 a1 [2] 12 aa [2] 09 e4 [2] 34 }

  condition:
    any of them
}