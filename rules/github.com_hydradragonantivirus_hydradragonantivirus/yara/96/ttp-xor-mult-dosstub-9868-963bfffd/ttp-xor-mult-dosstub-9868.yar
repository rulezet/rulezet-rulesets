rule TTP_XOR_MULT_DOSStub_9868 {
  strings:
    $key_9868 = { cc 00 [2] b8 18 [2] ff 1a [2] b8 0b [2] f6 07 [2] fa 0d [2] ed 06 [2] f6 48 [2] cb }

  condition:
    any of them
}