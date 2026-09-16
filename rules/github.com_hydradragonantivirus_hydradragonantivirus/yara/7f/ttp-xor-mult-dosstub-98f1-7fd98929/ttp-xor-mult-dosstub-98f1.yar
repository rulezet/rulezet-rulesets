rule TTP_XOR_MULT_DOSStub_98f1 {
  strings:
    $key_98f1 = { cc 99 [2] b8 81 [2] ff 83 [2] b8 92 [2] f6 9e [2] fa 94 [2] ed 9f [2] f6 d1 [2] cb }

  condition:
    any of them
}