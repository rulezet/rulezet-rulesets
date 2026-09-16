rule TTP_XOR_MULT_DOSStub_980d {
  strings:
    $key_980d = { cc 65 [2] b8 7d [2] ff 7f [2] b8 6e [2] f6 62 [2] fa 68 [2] ed 63 [2] f6 2d [2] cb }

  condition:
    any of them
}