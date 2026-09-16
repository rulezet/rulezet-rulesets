rule TTP_XOR_MULT_DOSStub_98e1 {
  strings:
    $key_98e1 = { cc 89 [2] b8 91 [2] ff 93 [2] b8 82 [2] f6 8e [2] fa 84 [2] ed 8f [2] f6 c1 [2] cb }

  condition:
    any of them
}