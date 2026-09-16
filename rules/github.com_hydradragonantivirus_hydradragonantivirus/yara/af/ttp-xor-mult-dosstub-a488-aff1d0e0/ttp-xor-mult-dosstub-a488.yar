rule TTP_XOR_MULT_DOSStub_a488 {
  strings:
    $key_a488 = { f0 e0 [2] 84 f8 [2] c3 fa [2] 84 eb [2] ca e7 [2] c6 ed [2] d1 e6 [2] ca a8 [2] f7 }

  condition:
    any of them
}