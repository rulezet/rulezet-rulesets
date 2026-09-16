rule TTP_XOR_MULT_DOSStub_98aa {
  strings:
    $key_98aa = { cc c2 [2] b8 da [2] ff d8 [2] b8 c9 [2] f6 c5 [2] fa cf [2] ed c4 [2] f6 8a [2] cb }

  condition:
    any of them
}