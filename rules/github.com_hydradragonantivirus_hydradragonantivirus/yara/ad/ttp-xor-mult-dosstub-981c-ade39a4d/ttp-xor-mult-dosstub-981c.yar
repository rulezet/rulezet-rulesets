rule TTP_XOR_MULT_DOSStub_981c {
  strings:
    $key_981c = { cc 74 [2] b8 6c [2] ff 6e [2] b8 7f [2] f6 73 [2] fa 79 [2] ed 72 [2] f6 3c [2] cb }

  condition:
    any of them
}