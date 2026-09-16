rule TTP_XOR_MULT_DOSStub_34c2 {
  strings:
    $key_34c2 = { 60 aa [2] 14 b2 [2] 53 b0 [2] 14 a1 [2] 5a ad [2] 56 a7 [2] 41 ac [2] 5a e2 [2] 67 }

  condition:
    any of them
}