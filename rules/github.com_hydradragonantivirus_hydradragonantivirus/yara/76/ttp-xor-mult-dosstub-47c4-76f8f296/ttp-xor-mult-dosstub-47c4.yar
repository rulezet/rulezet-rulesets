rule TTP_XOR_MULT_DOSStub_47c4 {
  strings:
    $key_47c4 = { 13 ac [2] 67 b4 [2] 20 b6 [2] 67 a7 [2] 29 ab [2] 25 a1 [2] 32 aa [2] 29 e4 [2] 14 }

  condition:
    any of them
}