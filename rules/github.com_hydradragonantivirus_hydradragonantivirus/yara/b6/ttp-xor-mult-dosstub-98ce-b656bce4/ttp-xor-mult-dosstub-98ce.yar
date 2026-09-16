rule TTP_XOR_MULT_DOSStub_98ce {
  strings:
    $key_98ce = { cc a6 [2] b8 be [2] ff bc [2] b8 ad [2] f6 a1 [2] fa ab [2] ed a0 [2] f6 ee [2] cb }

  condition:
    any of them
}