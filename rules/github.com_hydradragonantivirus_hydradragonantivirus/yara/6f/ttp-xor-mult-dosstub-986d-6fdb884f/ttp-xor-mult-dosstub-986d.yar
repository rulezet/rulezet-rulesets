rule TTP_XOR_MULT_DOSStub_986d {
  strings:
    $key_986d = { cc 05 [2] b8 1d [2] ff 1f [2] b8 0e [2] f6 02 [2] fa 08 [2] ed 03 [2] f6 4d [2] cb }

  condition:
    any of them
}