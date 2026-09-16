rule TTP_XOR_MULT_DOSStub_9806 {
  strings:
    $key_9806 = { cc 6e [2] b8 76 [2] ff 74 [2] b8 65 [2] f6 69 [2] fa 63 [2] ed 68 [2] f6 26 [2] cb }

  condition:
    any of them
}