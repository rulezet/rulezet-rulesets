rule TTP_XOR_MULT_DOSStub_9832 {
  strings:
    $key_9832 = { cc 5a [2] b8 42 [2] ff 40 [2] b8 51 [2] f6 5d [2] fa 57 [2] ed 5c [2] f6 12 [2] cb }

  condition:
    any of them
}