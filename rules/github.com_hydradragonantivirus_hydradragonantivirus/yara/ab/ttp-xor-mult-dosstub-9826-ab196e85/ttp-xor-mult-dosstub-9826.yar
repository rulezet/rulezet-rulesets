rule TTP_XOR_MULT_DOSStub_9826 {
  strings:
    $key_9826 = { cc 4e [2] b8 56 [2] ff 54 [2] b8 45 [2] f6 49 [2] fa 43 [2] ed 48 [2] f6 06 [2] cb }

  condition:
    any of them
}