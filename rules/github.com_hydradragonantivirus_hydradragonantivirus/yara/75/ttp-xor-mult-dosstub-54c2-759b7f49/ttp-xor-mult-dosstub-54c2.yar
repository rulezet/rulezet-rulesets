rule TTP_XOR_MULT_DOSStub_54c2 {
  strings:
    $key_54c2 = { 00 aa [2] 74 b2 [2] 33 b0 [2] 74 a1 [2] 3a ad [2] 36 a7 [2] 21 ac [2] 3a e2 [2] 07 }

  condition:
    any of them
}