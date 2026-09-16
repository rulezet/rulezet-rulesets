rule TTP_XOR_MULT_DOSStub_9834 {
  strings:
    $key_9834 = { cc 5c [2] b8 44 [2] ff 46 [2] b8 57 [2] f6 5b [2] fa 51 [2] ed 5a [2] f6 14 [2] cb }

  condition:
    any of them
}