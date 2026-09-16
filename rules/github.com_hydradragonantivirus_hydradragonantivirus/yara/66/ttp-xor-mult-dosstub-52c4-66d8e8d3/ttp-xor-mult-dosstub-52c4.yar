rule TTP_XOR_MULT_DOSStub_52c4 {
  strings:
    $key_52c4 = { 06 ac [2] 72 b4 [2] 35 b6 [2] 72 a7 [2] 3c ab [2] 30 a1 [2] 27 aa [2] 3c e4 [2] 01 }

  condition:
    any of them
}