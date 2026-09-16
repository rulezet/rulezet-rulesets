rule TTP_XOR_MULT_DOSStub_9858 {
  strings:
    $key_9858 = { cc 30 [2] b8 28 [2] ff 2a [2] b8 3b [2] f6 37 [2] fa 3d [2] ed 36 [2] f6 78 [2] cb }

  condition:
    any of them
}