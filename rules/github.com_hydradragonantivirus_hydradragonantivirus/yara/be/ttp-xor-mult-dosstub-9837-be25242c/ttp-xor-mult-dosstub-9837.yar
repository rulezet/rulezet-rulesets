rule TTP_XOR_MULT_DOSStub_9837 {
  strings:
    $key_9837 = { cc 5f [2] b8 47 [2] ff 45 [2] b8 54 [2] f6 58 [2] fa 52 [2] ed 59 [2] f6 17 [2] cb }

  condition:
    any of them
}