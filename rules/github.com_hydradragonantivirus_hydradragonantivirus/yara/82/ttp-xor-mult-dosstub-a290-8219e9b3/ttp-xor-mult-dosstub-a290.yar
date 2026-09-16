rule TTP_XOR_MULT_DOSStub_a290 {
  strings:
    $key_a290 = { f6 f8 [2] 82 e0 [2] c5 e2 [2] 82 f3 [2] cc ff [2] c0 f5 [2] d7 fe [2] cc b0 [2] f1 }

  condition:
    any of them
}