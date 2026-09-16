rule TTP_XOR_MULT_DOSStub_981e {
  strings:
    $key_981e = { cc 76 [2] b8 6e [2] ff 6c [2] b8 7d [2] f6 71 [2] fa 7b [2] ed 70 [2] f6 3e [2] cb }

  condition:
    any of them
}