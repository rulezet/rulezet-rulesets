rule TTP_XOR_MULT_DOSStub_c6c2 {
  strings:
    $key_c6c2 = { 92 aa [2] e6 b2 [2] a1 b0 [2] e6 a1 [2] a8 ad [2] a4 a7 [2] b3 ac [2] a8 e2 [2] 95 }

  condition:
    any of them
}