rule TTP_XOR_MULT_DOSStub_14c2 {
  strings:
    $key_14c2 = { 40 aa [2] 34 b2 [2] 73 b0 [2] 34 a1 [2] 7a ad [2] 76 a7 [2] 61 ac [2] 7a e2 [2] 47 }

  condition:
    any of them
}