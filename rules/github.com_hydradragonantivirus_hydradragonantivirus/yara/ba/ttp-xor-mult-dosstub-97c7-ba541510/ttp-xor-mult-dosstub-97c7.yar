rule TTP_XOR_MULT_DOSStub_97c7 {
  strings:
    $key_97c7 = { c3 af [2] b7 b7 [2] f0 b5 [2] b7 a4 [2] f9 a8 [2] f5 a2 [2] e2 a9 [2] f9 e7 [2] c4 }

  condition:
    any of them
}