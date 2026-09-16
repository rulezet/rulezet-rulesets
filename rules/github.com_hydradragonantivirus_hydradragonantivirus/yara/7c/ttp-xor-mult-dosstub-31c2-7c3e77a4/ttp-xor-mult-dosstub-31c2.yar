rule TTP_XOR_MULT_DOSStub_31c2 {
  strings:
    $key_31c2 = { 65 aa [2] 11 b2 [2] 56 b0 [2] 11 a1 [2] 5f ad [2] 53 a7 [2] 44 ac [2] 5f e2 [2] 62 }

  condition:
    any of them
}