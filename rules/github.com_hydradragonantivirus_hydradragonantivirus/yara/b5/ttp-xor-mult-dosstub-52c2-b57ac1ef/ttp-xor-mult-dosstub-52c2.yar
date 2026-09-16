rule TTP_XOR_MULT_DOSStub_52c2 {
  strings:
    $key_52c2 = { 06 aa [2] 72 b2 [2] 35 b0 [2] 72 a1 [2] 3c ad [2] 30 a7 [2] 27 ac [2] 3c e2 [2] 01 }

  condition:
    any of them
}