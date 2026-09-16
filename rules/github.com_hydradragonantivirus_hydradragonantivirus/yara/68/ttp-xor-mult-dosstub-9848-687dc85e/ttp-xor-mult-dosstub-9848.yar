rule TTP_XOR_MULT_DOSStub_9848 {
  strings:
    $key_9848 = { cc 20 [2] b8 38 [2] ff 3a [2] b8 2b [2] f6 27 [2] fa 2d [2] ed 26 [2] f6 68 [2] cb }

  condition:
    any of them
}