rule TTP_XOR_MULT_DOSStub_98c0 {
  strings:
    $key_98c0 = { cc a8 [2] b8 b0 [2] ff b2 [2] b8 a3 [2] f6 af [2] fa a5 [2] ed ae [2] f6 e0 [2] cb }

  condition:
    any of them
}