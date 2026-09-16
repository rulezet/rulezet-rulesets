rule TTP_XOR_MULT_DOSStub_a485 {
  strings:
    $key_a485 = { f0 ed [2] 84 f5 [2] c3 f7 [2] 84 e6 [2] ca ea [2] c6 e0 [2] d1 eb [2] ca a5 [2] f7 }

  condition:
    any of them
}