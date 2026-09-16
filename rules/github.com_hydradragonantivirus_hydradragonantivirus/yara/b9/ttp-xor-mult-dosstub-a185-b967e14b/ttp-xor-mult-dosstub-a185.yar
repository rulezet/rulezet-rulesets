rule TTP_XOR_MULT_DOSStub_a185 {
  strings:
    $key_a185 = { f5 ed [2] 81 f5 [2] c6 f7 [2] 81 e6 [2] cf ea [2] c3 e0 [2] d4 eb [2] cf a5 [2] f2 }

  condition:
    any of them
}