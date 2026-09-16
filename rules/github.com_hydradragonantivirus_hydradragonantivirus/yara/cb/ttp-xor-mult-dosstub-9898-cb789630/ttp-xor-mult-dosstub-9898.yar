rule TTP_XOR_MULT_DOSStub_9898 {
  strings:
    $key_9898 = { cc f0 [2] b8 e8 [2] ff ea [2] b8 fb [2] f6 f7 [2] fa fd [2] ed f6 [2] f6 b8 [2] cb }

  condition:
    any of them
}