rule TTP_XOR_MULT_DOSStub_9822 {
  strings:
    $key_9822 = { cc 4a [2] b8 52 [2] ff 50 [2] b8 41 [2] f6 4d [2] fa 47 [2] ed 4c [2] f6 02 [2] cb }

  condition:
    any of them
}