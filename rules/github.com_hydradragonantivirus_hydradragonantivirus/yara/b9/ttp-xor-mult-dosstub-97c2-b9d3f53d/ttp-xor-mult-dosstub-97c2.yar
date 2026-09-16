rule TTP_XOR_MULT_DOSStub_97c2 {
  strings:
    $key_97c2 = { c3 aa [2] b7 b2 [2] f0 b0 [2] b7 a1 [2] f9 ad [2] f5 a7 [2] e2 ac [2] f9 e2 [2] c4 }

  condition:
    any of them
}