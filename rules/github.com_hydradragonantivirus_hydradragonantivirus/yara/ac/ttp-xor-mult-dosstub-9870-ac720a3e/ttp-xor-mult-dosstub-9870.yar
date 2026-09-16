rule TTP_XOR_MULT_DOSStub_9870 {
  strings:
    $key_9870 = { cc 18 [2] b8 00 [2] ff 02 [2] b8 13 [2] f6 1f [2] fa 15 [2] ed 1e [2] f6 50 [2] cb }

  condition:
    any of them
}