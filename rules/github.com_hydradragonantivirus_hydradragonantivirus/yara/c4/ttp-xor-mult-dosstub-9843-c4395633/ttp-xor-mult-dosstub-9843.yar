rule TTP_XOR_MULT_DOSStub_9843 {
  strings:
    $key_9843 = { cc 2b [2] b8 33 [2] ff 31 [2] b8 20 [2] f6 2c [2] fa 26 [2] ed 2d [2] f6 63 [2] cb }

  condition:
    any of them
}