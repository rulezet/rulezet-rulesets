rule TTP_XOR_MULT_DOSStub_98fb {
  strings:
    $key_98fb = { cc 93 [2] b8 8b [2] ff 89 [2] b8 98 [2] f6 94 [2] fa 9e [2] ed 95 [2] f6 db [2] cb }

  condition:
    any of them
}