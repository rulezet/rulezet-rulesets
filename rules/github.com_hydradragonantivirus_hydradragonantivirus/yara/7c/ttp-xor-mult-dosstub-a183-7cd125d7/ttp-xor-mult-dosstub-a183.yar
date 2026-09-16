rule TTP_XOR_MULT_DOSStub_a183 {
  strings:
    $key_a183 = { f5 eb [2] 81 f3 [2] c6 f1 [2] 81 e0 [2] cf ec [2] c3 e6 [2] d4 ed [2] cf a3 [2] f2 }

  condition:
    any of them
}