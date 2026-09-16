rule TTP_XOR_MULT_DOSStub_9836 {
  strings:
    $key_9836 = { cc 5e [2] b8 46 [2] ff 44 [2] b8 55 [2] f6 59 [2] fa 53 [2] ed 58 [2] f6 16 [2] cb }

  condition:
    any of them
}