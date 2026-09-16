rule TTP_XOR_MULT_DOSStub_56c4 {
  strings:
    $key_56c4 = { 02 ac [2] 76 b4 [2] 31 b6 [2] 76 a7 [2] 38 ab [2] 34 a1 [2] 23 aa [2] 38 e4 [2] 05 }

  condition:
    any of them
}