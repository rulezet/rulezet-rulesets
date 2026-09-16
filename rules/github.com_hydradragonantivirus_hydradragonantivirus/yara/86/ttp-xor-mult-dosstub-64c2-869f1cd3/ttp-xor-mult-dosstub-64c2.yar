rule TTP_XOR_MULT_DOSStub_64c2 {
  strings:
    $key_64c2 = { 30 aa [2] 44 b2 [2] 03 b0 [2] 44 a1 [2] 0a ad [2] 06 a7 [2] 11 ac [2] 0a e2 [2] 37 }

  condition:
    any of them
}