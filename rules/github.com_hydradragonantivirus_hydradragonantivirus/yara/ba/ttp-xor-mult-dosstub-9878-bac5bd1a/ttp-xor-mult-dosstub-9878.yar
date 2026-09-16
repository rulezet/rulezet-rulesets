rule TTP_XOR_MULT_DOSStub_9878 {
  strings:
    $key_9878 = { cc 10 [2] b8 08 [2] ff 0a [2] b8 1b [2] f6 17 [2] fa 1d [2] ed 16 [2] f6 58 [2] cb }

  condition:
    any of them
}