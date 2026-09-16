rule TTP_XOR_MULT_DOSStub_a2c7 {
  strings:
    $key_a2c7 = { f6 af [2] 82 b7 [2] c5 b5 [2] 82 a4 [2] cc a8 [2] c0 a2 [2] d7 a9 [2] cc e7 [2] f1 }

  condition:
    any of them
}