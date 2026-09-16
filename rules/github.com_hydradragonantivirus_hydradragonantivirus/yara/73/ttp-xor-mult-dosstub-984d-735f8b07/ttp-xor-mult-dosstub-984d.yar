rule TTP_XOR_MULT_DOSStub_984d {
  strings:
    $key_984d = { cc 25 [2] b8 3d [2] ff 3f [2] b8 2e [2] f6 22 [2] fa 28 [2] ed 23 [2] f6 6d [2] cb }

  condition:
    any of them
}