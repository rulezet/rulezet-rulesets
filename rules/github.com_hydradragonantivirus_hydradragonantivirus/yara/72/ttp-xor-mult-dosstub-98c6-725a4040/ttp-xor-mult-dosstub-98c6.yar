rule TTP_XOR_MULT_DOSStub_98c6 {
  strings:
    $key_98c6 = { cc ae [2] b8 b6 [2] ff b4 [2] b8 a5 [2] f6 a9 [2] fa a3 [2] ed a8 [2] f6 e6 [2] cb }

  condition:
    any of them
}