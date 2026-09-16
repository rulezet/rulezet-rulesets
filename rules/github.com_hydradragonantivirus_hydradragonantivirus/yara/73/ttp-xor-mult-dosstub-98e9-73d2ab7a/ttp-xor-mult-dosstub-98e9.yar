rule TTP_XOR_MULT_DOSStub_98e9 {
  strings:
    $key_98e9 = { cc 81 [2] b8 99 [2] ff 9b [2] b8 8a [2] f6 86 [2] fa 8c [2] ed 87 [2] f6 c9 [2] cb }

  condition:
    any of them
}