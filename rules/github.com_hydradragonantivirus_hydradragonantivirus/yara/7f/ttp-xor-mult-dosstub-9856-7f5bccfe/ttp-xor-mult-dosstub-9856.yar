rule TTP_XOR_MULT_DOSStub_9856 {
  strings:
    $key_9856 = { cc 3e [2] b8 26 [2] ff 24 [2] b8 35 [2] f6 39 [2] fa 33 [2] ed 38 [2] f6 76 [2] cb }

  condition:
    any of them
}