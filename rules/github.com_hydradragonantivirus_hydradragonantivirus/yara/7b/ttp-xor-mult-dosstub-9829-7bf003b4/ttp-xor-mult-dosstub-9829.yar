rule TTP_XOR_MULT_DOSStub_9829 {
  strings:
    $key_9829 = { cc 41 [2] b8 59 [2] ff 5b [2] b8 4a [2] f6 46 [2] fa 4c [2] ed 47 [2] f6 09 [2] cb }

  condition:
    any of them
}