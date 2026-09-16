rule TTP_XOR_MULT_DOSStub_9808 {
  strings:
    $key_9808 = { cc 60 [2] b8 78 [2] ff 7a [2] b8 6b [2] f6 67 [2] fa 6d [2] ed 66 [2] f6 28 [2] cb }

  condition:
    any of them
}