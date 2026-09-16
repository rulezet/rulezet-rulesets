rule TTP_XOR_MULT_DOSStub_23c2 {
  strings:
    $key_23c2 = { 77 aa [2] 03 b2 [2] 44 b0 [2] 03 a1 [2] 4d ad [2] 41 a7 [2] 56 ac [2] 4d e2 [2] 70 }

  condition:
    any of them
}