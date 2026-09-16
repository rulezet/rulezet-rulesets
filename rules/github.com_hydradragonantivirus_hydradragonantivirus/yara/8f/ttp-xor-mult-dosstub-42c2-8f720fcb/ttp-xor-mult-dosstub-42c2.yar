rule TTP_XOR_MULT_DOSStub_42c2 {
  strings:
    $key_42c2 = { 16 aa [2] 62 b2 [2] 25 b0 [2] 62 a1 [2] 2c ad [2] 20 a7 [2] 37 ac [2] 2c e2 [2] 11 }

  condition:
    any of them
}