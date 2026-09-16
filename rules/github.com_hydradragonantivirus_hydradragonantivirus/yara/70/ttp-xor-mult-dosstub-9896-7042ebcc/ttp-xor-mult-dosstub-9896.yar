rule TTP_XOR_MULT_DOSStub_9896 {
  strings:
    $key_9896 = { cc fe [2] b8 e6 [2] ff e4 [2] b8 f5 [2] f6 f9 [2] fa f3 [2] ed f8 [2] f6 b6 [2] cb }

  condition:
    any of them
}