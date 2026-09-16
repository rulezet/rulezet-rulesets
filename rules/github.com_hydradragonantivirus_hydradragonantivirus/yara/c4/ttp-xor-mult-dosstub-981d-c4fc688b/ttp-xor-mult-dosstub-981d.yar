rule TTP_XOR_MULT_DOSStub_981d {
  strings:
    $key_981d = { cc 75 [2] b8 6d [2] ff 6f [2] b8 7e [2] f6 72 [2] fa 78 [2] ed 73 [2] f6 3d [2] cb }

  condition:
    any of them
}