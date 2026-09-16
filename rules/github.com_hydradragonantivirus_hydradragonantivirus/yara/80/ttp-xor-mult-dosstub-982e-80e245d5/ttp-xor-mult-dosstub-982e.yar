rule TTP_XOR_MULT_DOSStub_982e {
  strings:
    $key_982e = { cc 46 [2] b8 5e [2] ff 5c [2] b8 4d [2] f6 41 [2] fa 4b [2] ed 40 [2] f6 0e [2] cb }

  condition:
    any of them
}