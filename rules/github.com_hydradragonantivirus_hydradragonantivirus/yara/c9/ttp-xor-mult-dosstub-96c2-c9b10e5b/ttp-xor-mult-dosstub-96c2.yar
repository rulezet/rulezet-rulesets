rule TTP_XOR_MULT_DOSStub_96c2 {
  strings:
    $key_96c2 = { c2 aa [2] b6 b2 [2] f1 b0 [2] b6 a1 [2] f8 ad [2] f4 a7 [2] e3 ac [2] f8 e2 [2] c5 }

  condition:
    any of them
}