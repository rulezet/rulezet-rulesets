rule TTP_XOR_MULT_DOSStub_a783 {
  strings:
    $key_a783 = { f3 eb [2] 87 f3 [2] c0 f1 [2] 87 e0 [2] c9 ec [2] c5 e6 [2] d2 ed [2] c9 a3 [2] f4 }

  condition:
    any of them
}