rule TTP_XOR_MULT_DOSStub_32c2 {
  strings:
    $key_32c2 = { 66 aa [2] 12 b2 [2] 55 b0 [2] 12 a1 [2] 5c ad [2] 50 a7 [2] 47 ac [2] 5c e2 [2] 61 }

  condition:
    any of them
}