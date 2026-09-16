rule TTP_XOR_MULT_DOSStub_9881 {
  strings:
    $key_9881 = { cc e9 [2] b8 f1 [2] ff f3 [2] b8 e2 [2] f6 ee [2] fa e4 [2] ed ef [2] f6 a1 [2] cb }

  condition:
    any of them
}