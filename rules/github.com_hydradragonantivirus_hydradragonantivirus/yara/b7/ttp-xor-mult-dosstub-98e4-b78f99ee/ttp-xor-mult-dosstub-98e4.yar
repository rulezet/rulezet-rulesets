rule TTP_XOR_MULT_DOSStub_98e4 {
  strings:
    $key_98e4 = { cc 8c [2] b8 94 [2] ff 96 [2] b8 87 [2] f6 8b [2] fa 81 [2] ed 8a [2] f6 c4 [2] cb }

  condition:
    any of them
}