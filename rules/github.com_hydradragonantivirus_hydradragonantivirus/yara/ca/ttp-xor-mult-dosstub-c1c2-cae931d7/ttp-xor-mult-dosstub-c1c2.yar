rule TTP_XOR_MULT_DOSStub_c1c2 {
  strings:
    $key_c1c2 = { 95 aa [2] e1 b2 [2] a6 b0 [2] e1 a1 [2] af ad [2] a3 a7 [2] b4 ac [2] af e2 [2] 92 }

  condition:
    any of them
}