rule TTP_XOR_MULT_DOSStub_02c2 {
  strings:
    $key_02c2 = { 56 aa [2] 22 b2 [2] 65 b0 [2] 22 a1 [2] 6c ad [2] 60 a7 [2] 77 ac [2] 6c e2 [2] 51 }

  condition:
    any of them
}