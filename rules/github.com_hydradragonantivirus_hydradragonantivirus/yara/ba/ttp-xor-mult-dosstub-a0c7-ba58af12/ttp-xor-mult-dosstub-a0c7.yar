rule TTP_XOR_MULT_DOSStub_a0c7 {
  strings:
    $key_a0c7 = { f4 af [2] 80 b7 [2] c7 b5 [2] 80 a4 [2] ce a8 [2] c2 a2 [2] d5 a9 [2] ce e7 [2] f3 }

  condition:
    any of them
}