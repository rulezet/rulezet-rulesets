rule TTP_XOR_MULT_DOSStub_9820 {
  strings:
    $key_9820 = { cc 48 [2] b8 50 [2] ff 52 [2] b8 43 [2] f6 4f [2] fa 45 [2] ed 4e [2] f6 00 [2] cb }

  condition:
    any of them
}