rule TTP_XOR_MULT_DOSStub_98e8 {
  strings:
    $key_98e8 = { cc 80 [2] b8 98 [2] ff 9a [2] b8 8b [2] f6 87 [2] fa 8d [2] ed 86 [2] f6 c8 [2] cb }

  condition:
    any of them
}