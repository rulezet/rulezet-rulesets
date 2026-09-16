rule TTP_XOR_MULT_DOSStub_c7c2 {
  strings:
    $key_c7c2 = { 93 aa [2] e7 b2 [2] a0 b0 [2] e7 a1 [2] a9 ad [2] a5 a7 [2] b2 ac [2] a9 e2 [2] 94 }

  condition:
    any of them
}