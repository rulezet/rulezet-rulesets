rule TTP_XOR_MULT_DOSStub_56c2 {
  strings:
    $key_56c2 = { 02 aa [2] 76 b2 [2] 31 b0 [2] 76 a1 [2] 38 ad [2] 34 a7 [2] 23 ac [2] 38 e2 [2] 05 }

  condition:
    any of them
}