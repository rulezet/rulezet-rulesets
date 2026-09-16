rule TTP_XOR_MULT_DOSStub_44c2 {
  strings:
    $key_44c2 = { 10 aa [2] 64 b2 [2] 23 b0 [2] 64 a1 [2] 2a ad [2] 26 a7 [2] 31 ac [2] 2a e2 [2] 17 }

  condition:
    any of them
}