rule TTP_XOR_MULT_DOSStub_9890 {
  strings:
    $key_9890 = { cc f8 [2] b8 e0 [2] ff e2 [2] b8 f3 [2] f6 ff [2] fa f5 [2] ed fe [2] f6 b0 [2] cb }

  condition:
    any of them
}