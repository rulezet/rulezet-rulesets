rule TTP_XOR_MULT_DOSStub_9833 {
  strings:
    $key_9833 = { cc 5b [2] b8 43 [2] ff 41 [2] b8 50 [2] f6 5c [2] fa 56 [2] ed 5d [2] f6 13 [2] cb }

  condition:
    any of them
}