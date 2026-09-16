rule TTP_XOR_MULT_DOSStub_a785 {
  strings:
    $key_a785 = { f3 ed [2] 87 f5 [2] c0 f7 [2] 87 e6 [2] c9 ea [2] c5 e0 [2] d2 eb [2] c9 a5 [2] f4 }

  condition:
    any of them
}