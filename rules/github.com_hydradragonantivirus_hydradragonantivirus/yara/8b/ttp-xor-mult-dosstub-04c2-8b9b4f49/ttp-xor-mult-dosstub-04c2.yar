rule TTP_XOR_MULT_DOSStub_04c2 {
  strings:
    $key_04c2 = { 50 aa [2] 24 b2 [2] 63 b0 [2] 24 a1 [2] 6a ad [2] 66 a7 [2] 71 ac [2] 6a e2 [2] 57 }

  condition:
    any of them
}