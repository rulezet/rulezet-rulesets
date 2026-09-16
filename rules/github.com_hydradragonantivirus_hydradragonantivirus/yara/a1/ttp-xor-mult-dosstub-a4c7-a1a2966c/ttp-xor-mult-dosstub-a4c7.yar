rule TTP_XOR_MULT_DOSStub_a4c7 {
  strings:
    $key_a4c7 = { f0 af [2] 84 b7 [2] c3 b5 [2] 84 a4 [2] ca a8 [2] c6 a2 [2] d1 a9 [2] ca e7 [2] f7 }

  condition:
    any of them
}