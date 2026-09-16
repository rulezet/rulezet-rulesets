rule TTP_XOR_MULT_DOSStub_9862 {
  strings:
    $key_9862 = { cc 0a [2] b8 12 [2] ff 10 [2] b8 01 [2] f6 0d [2] fa 07 [2] ed 0c [2] f6 42 [2] cb }

  condition:
    any of them
}