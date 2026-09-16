rule TTP_XOR_MULT_DOSStub_9850 {
  strings:
    $key_9850 = { cc 38 [2] b8 20 [2] ff 22 [2] b8 33 [2] f6 3f [2] fa 35 [2] ed 3e [2] f6 70 [2] cb }

  condition:
    any of them
}