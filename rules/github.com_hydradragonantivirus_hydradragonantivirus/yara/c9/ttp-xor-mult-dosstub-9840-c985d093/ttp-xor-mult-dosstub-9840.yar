rule TTP_XOR_MULT_DOSStub_9840 {
  strings:
    $key_9840 = { cc 28 [2] b8 30 [2] ff 32 [2] b8 23 [2] f6 2f [2] fa 25 [2] ed 2e [2] f6 60 [2] cb }

  condition:
    any of them
}