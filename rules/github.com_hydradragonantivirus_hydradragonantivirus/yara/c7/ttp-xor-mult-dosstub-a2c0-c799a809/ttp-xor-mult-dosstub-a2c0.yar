rule TTP_XOR_MULT_DOSStub_a2c0 {
  strings:
    $key_a2c0 = { f6 a8 [2] 82 b0 [2] c5 b2 [2] 82 a3 [2] cc af [2] c0 a5 [2] d7 ae [2] cc e0 [2] f1 }

  condition:
    any of them
}