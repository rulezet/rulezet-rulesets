rule TTP_XOR_MULT_DOSStub_98f0 {
  strings:
    $key_98f0 = { cc 98 [2] b8 80 [2] ff 82 [2] b8 93 [2] f6 9f [2] fa 95 [2] ed 9e [2] f6 d0 [2] cb }

  condition:
    any of them
}