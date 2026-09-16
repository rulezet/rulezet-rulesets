rule TTP_XOR_MULT_DOSStub_9879 {
  strings:
    $key_9879 = { cc 11 [2] b8 09 [2] ff 0b [2] b8 1a [2] f6 16 [2] fa 1c [2] ed 17 [2] f6 59 [2] cb }

  condition:
    any of them
}