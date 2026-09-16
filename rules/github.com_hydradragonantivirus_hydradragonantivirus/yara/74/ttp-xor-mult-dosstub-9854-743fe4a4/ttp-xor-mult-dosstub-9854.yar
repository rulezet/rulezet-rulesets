rule TTP_XOR_MULT_DOSStub_9854 {
  strings:
    $key_9854 = { cc 3c [2] b8 24 [2] ff 26 [2] b8 37 [2] f6 3b [2] fa 31 [2] ed 3a [2] f6 74 [2] cb }

  condition:
    any of them
}