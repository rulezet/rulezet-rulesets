rule TTP_XOR_MULT_DOSStub_a788 {
  strings:
    $key_a788 = { f3 e0 [2] 87 f8 [2] c0 fa [2] 87 eb [2] c9 e7 [2] c5 ed [2] d2 e6 [2] c9 a8 [2] f4 }

  condition:
    any of them
}