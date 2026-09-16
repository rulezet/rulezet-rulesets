rule TTP_XOR_MULT_DOSStub_9864 {
  strings:
    $key_9864 = { cc 0c [2] b8 14 [2] ff 16 [2] b8 07 [2] f6 0b [2] fa 01 [2] ed 0a [2] f6 44 [2] cb }

  condition:
    any of them
}