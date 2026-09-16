rule TTP_XOR_MULT_DOSStub_a2c1 {
  strings:
    $key_a2c1 = { f6 a9 [2] 82 b1 [2] c5 b3 [2] 82 a2 [2] cc ae [2] c0 a4 [2] d7 af [2] cc e1 [2] f1 }

  condition:
    any of them
}