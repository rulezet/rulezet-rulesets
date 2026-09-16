rule TTP_XOR_MULT_DOSStub_9828 {
  strings:
    $key_9828 = { cc 40 [2] b8 58 [2] ff 5a [2] b8 4b [2] f6 47 [2] fa 4d [2] ed 46 [2] f6 08 [2] cb }

  condition:
    any of them
}