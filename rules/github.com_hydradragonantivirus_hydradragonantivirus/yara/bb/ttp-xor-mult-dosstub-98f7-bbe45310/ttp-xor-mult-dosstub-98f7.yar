rule TTP_XOR_MULT_DOSStub_98f7 {
  strings:
    $key_98f7 = { cc 9f [2] b8 87 [2] ff 85 [2] b8 94 [2] f6 98 [2] fa 92 [2] ed 99 [2] f6 d7 [2] cb }

  condition:
    any of them
}