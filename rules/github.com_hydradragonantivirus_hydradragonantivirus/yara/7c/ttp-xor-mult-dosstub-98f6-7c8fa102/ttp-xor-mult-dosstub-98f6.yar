rule TTP_XOR_MULT_DOSStub_98f6 {
  strings:
    $key_98f6 = { cc 9e [2] b8 86 [2] ff 84 [2] b8 95 [2] f6 99 [2] fa 93 [2] ed 98 [2] f6 d6 [2] cb }

  condition:
    any of them
}