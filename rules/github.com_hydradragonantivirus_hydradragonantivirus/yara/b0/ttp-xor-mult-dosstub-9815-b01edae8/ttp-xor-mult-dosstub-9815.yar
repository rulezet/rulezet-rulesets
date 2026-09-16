rule TTP_XOR_MULT_DOSStub_9815 {
  strings:
    $key_9815 = { cc 7d [2] b8 65 [2] ff 67 [2] b8 76 [2] f6 7a [2] fa 70 [2] ed 7b [2] f6 35 [2] cb }

  condition:
    any of them
}