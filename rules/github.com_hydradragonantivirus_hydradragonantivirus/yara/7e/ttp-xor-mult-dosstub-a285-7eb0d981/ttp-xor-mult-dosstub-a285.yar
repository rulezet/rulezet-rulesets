rule TTP_XOR_MULT_DOSStub_a285 {
  strings:
    $key_a285 = { f6 ed [2] 82 f5 [2] c5 f7 [2] 82 e6 [2] cc ea [2] c0 e0 [2] d7 eb [2] cc a5 [2] f1 }

  condition:
    any of them
}