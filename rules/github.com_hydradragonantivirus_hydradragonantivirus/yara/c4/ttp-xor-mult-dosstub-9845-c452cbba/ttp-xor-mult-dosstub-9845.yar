rule TTP_XOR_MULT_DOSStub_9845 {
  strings:
    $key_9845 = { cc 2d [2] b8 35 [2] ff 37 [2] b8 26 [2] f6 2a [2] fa 20 [2] ed 2b [2] f6 65 [2] cb }

  condition:
    any of them
}