rule TTP_XOR_MULT_DOSStub_983c {
  strings:
    $key_983c = { cc 54 [2] b8 4c [2] ff 4e [2] b8 5f [2] f6 53 [2] fa 59 [2] ed 52 [2] f6 1c [2] cb }

  condition:
    any of them
}