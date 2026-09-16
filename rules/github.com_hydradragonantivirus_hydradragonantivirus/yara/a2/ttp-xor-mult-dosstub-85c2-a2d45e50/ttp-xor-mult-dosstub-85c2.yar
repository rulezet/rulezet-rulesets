rule TTP_XOR_MULT_DOSStub_85c2 {
  strings:
    $key_85c2 = { d1 aa [2] a5 b2 [2] e2 b0 [2] a5 a1 [2] eb ad [2] e7 a7 [2] f0 ac [2] eb e2 [2] d6 }

  condition:
    any of them
}