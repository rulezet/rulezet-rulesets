rule TTP_XOR_MULT_DOSStub_98d9 {
  strings:
    $key_98d9 = { cc b1 [2] b8 a9 [2] ff ab [2] b8 ba [2] f6 b6 [2] fa bc [2] ed b7 [2] f6 f9 [2] cb }

  condition:
    any of them
}