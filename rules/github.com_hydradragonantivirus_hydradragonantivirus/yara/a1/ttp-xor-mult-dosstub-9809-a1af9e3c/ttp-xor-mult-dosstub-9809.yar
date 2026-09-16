rule TTP_XOR_MULT_DOSStub_9809 {
  strings:
    $key_9809 = { cc 61 [2] b8 79 [2] ff 7b [2] b8 6a [2] f6 66 [2] fa 6c [2] ed 67 [2] f6 29 [2] cb }

  condition:
    any of them
}