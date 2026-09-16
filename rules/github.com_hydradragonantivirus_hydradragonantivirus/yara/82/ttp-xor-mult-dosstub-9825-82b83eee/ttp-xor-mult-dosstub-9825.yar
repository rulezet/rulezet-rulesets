rule TTP_XOR_MULT_DOSStub_9825 {
  strings:
    $key_9825 = { cc 4d [2] b8 55 [2] ff 57 [2] b8 46 [2] f6 4a [2] fa 40 [2] ed 4b [2] f6 05 [2] cb }

  condition:
    any of them
}