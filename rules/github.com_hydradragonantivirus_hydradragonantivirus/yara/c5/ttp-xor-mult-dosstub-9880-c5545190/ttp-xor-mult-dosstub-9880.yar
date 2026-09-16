rule TTP_XOR_MULT_DOSStub_9880 {
  strings:
    $key_9880 = { cc e8 [2] b8 f0 [2] ff f2 [2] b8 e3 [2] f6 ef [2] fa e5 [2] ed ee [2] f6 a0 [2] cb }

  condition:
    any of them
}