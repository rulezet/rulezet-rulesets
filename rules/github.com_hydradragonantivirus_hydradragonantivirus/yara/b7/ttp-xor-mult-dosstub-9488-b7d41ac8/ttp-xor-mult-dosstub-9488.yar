rule TTP_XOR_MULT_DOSStub_9488 {
  strings:
    $key_9488 = { c0 e0 [2] b4 f8 [2] f3 fa [2] b4 eb [2] fa e7 [2] f6 ed [2] e1 e6 [2] fa a8 [2] c7 }

  condition:
    any of them
}