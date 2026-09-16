rule TTP_XOR_MULT_DOSStub_a596 {
  strings:
    $key_a596 = { f1 fe [2] 85 e6 [2] c2 e4 [2] 85 f5 [2] cb f9 [2] c7 f3 [2] d0 f8 [2] cb b6 [2] f6 }

  condition:
    any of them
}