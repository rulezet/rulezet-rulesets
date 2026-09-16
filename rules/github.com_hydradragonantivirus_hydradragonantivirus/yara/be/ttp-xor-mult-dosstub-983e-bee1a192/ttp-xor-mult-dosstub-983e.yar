rule TTP_XOR_MULT_DOSStub_983e {
  strings:
    $key_983e = { cc 56 [2] b8 4e [2] ff 4c [2] b8 5d [2] f6 51 [2] fa 5b [2] ed 50 [2] f6 1e [2] cb }

  condition:
    any of them
}