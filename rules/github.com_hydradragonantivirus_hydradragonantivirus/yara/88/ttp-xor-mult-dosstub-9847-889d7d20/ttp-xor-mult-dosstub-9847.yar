rule TTP_XOR_MULT_DOSStub_9847 {
  strings:
    $key_9847 = { cc 2f [2] b8 37 [2] ff 35 [2] b8 24 [2] f6 28 [2] fa 22 [2] ed 29 [2] f6 67 [2] cb }

  condition:
    any of them
}