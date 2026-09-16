rule TTP_XOR_MULT_DOSStub_981f {
  strings:
    $key_981f = { cc 77 [2] b8 6f [2] ff 6d [2] b8 7c [2] f6 70 [2] fa 7a [2] ed 71 [2] f6 3f [2] cb }

  condition:
    any of them
}