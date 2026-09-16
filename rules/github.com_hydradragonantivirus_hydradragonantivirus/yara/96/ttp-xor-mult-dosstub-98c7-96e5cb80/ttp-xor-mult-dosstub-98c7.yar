rule TTP_XOR_MULT_DOSStub_98c7 {
  strings:
    $key_98c7 = { cc af [2] b8 b7 [2] ff b5 [2] b8 a4 [2] f6 a8 [2] fa a2 [2] ed a9 [2] f6 e7 [2] cb }

  condition:
    any of them
}