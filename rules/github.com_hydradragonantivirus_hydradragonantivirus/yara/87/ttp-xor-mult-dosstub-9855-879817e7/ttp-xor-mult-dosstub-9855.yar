rule TTP_XOR_MULT_DOSStub_9855 {
  strings:
    $key_9855 = { cc 3d [2] b8 25 [2] ff 27 [2] b8 36 [2] f6 3a [2] fa 30 [2] ed 3b [2] f6 75 [2] cb }

  condition:
    any of them
}