rule TTP_XOR_MULT_DOSStub_9859 {
  strings:
    $key_9859 = { cc 31 [2] b8 29 [2] ff 2b [2] b8 3a [2] f6 36 [2] fa 3c [2] ed 37 [2] f6 79 [2] cb }

  condition:
    any of them
}