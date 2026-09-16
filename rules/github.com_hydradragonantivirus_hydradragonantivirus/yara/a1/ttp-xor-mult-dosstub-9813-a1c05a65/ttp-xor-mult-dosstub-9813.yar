rule TTP_XOR_MULT_DOSStub_9813 {
  strings:
    $key_9813 = { cc 7b [2] b8 63 [2] ff 61 [2] b8 70 [2] f6 7c [2] fa 76 [2] ed 7d [2] f6 33 [2] cb }

  condition:
    any of them
}