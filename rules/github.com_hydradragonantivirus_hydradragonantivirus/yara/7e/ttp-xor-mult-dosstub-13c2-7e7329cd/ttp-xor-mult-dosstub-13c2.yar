rule TTP_XOR_MULT_DOSStub_13c2 {
  strings:
    $key_13c2 = { 47 aa [2] 33 b2 [2] 74 b0 [2] 33 a1 [2] 7d ad [2] 71 a7 [2] 66 ac [2] 7d e2 [2] 40 }

  condition:
    any of them
}