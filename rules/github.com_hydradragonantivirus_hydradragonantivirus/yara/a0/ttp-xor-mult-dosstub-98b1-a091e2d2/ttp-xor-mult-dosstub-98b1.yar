rule TTP_XOR_MULT_DOSStub_98b1 {
  strings:
    $key_98b1 = { cc d9 [2] b8 c1 [2] ff c3 [2] b8 d2 [2] f6 de [2] fa d4 [2] ed df [2] f6 91 [2] cb }

  condition:
    any of them
}