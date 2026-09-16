rule TTP_XOR_MULT_DOSStub_98c4 {
  strings:
    $key_98c4 = { cc ac [2] b8 b4 [2] ff b6 [2] b8 a7 [2] f6 ab [2] fa a1 [2] ed aa [2] f6 e4 [2] cb }

  condition:
    any of them
}