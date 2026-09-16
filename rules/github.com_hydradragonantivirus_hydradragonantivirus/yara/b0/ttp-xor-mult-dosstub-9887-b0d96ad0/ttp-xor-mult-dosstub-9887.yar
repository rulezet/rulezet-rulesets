rule TTP_XOR_MULT_DOSStub_9887 {
  strings:
    $key_9887 = { cc ef [2] b8 f7 [2] ff f5 [2] b8 e4 [2] f6 e8 [2] fa e2 [2] ed e9 [2] f6 a7 [2] cb }

  condition:
    any of them
}