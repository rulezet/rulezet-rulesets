rule TTP_XOR_MULT_DOSStub_9893 {
  strings:
    $key_9893 = { cc fb [2] b8 e3 [2] ff e1 [2] b8 f0 [2] f6 fc [2] fa f6 [2] ed fd [2] f6 b3 [2] cb }

  condition:
    any of them
}