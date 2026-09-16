rule TTP_XOR_MULT_DOSStub_9486 {
  strings:
    $key_9486 = { c0 ee [2] b4 f6 [2] f3 f4 [2] b4 e5 [2] fa e9 [2] f6 e3 [2] e1 e8 [2] fa a6 [2] c7 }

  condition:
    any of them
}