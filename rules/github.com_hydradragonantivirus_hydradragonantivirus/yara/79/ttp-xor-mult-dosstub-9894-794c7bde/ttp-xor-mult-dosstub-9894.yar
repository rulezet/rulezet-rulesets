rule TTP_XOR_MULT_DOSStub_9894 {
  strings:
    $key_9894 = { cc fc [2] b8 e4 [2] ff e6 [2] b8 f7 [2] f6 fb [2] fa f1 [2] ed fa [2] f6 b4 [2] cb }

  condition:
    any of them
}