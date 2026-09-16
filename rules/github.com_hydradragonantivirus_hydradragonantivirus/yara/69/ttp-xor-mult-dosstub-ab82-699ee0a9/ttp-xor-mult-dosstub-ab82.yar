rule TTP_XOR_MULT_DOSStub_ab82 {
  strings:
    $key_ab82 = { ff ea [2] 8b f2 [2] cc f0 [2] 8b e1 [2] c5 ed [2] c9 e7 [2] de ec [2] c5 a2 [2] f8 }

  condition:
    any of them
}