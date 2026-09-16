rule TTP_XOR_MULT_DOSStub_a088 {
  strings:
    $key_a088 = { f4 e0 [2] 80 f8 [2] c7 fa [2] 80 eb [2] ce e7 [2] c2 ed [2] d5 e6 [2] ce a8 [2] f3 }

  condition:
    any of them
}