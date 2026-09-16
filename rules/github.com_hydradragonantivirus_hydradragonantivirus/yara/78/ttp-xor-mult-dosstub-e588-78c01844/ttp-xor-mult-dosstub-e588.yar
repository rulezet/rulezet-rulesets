rule TTP_XOR_MULT_DOSStub_e588 {
  strings:
    $key_e588 = { b1 e0 [2] c5 f8 [2] 82 fa [2] c5 eb [2] 8b e7 [2] 87 ed [2] 90 e6 [2] 8b a8 [2] b6 }

  condition:
    any of them
}