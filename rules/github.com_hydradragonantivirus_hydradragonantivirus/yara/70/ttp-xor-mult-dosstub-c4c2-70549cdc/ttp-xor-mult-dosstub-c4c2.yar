rule TTP_XOR_MULT_DOSStub_c4c2 {
  strings:
    $key_c4c2 = { 90 aa [2] e4 b2 [2] a3 b0 [2] e4 a1 [2] aa ad [2] a6 a7 [2] b1 ac [2] aa e2 [2] 97 }

  condition:
    any of them
}