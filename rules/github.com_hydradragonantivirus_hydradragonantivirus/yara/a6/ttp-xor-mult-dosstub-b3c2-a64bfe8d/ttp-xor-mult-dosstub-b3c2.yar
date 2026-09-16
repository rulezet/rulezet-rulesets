rule TTP_XOR_MULT_DOSStub_b3c2 {
  strings:
    $key_b3c2 = { e7 aa [2] 93 b2 [2] d4 b0 [2] 93 a1 [2] dd ad [2] d1 a7 [2] c6 ac [2] dd e2 [2] e0 }

  condition:
    any of them
}