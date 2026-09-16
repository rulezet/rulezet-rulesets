rule TTP_XOR_MULT_DOSStub_986f {
  strings:
    $key_986f = { cc 07 [2] b8 1f [2] ff 1d [2] b8 0c [2] f6 00 [2] fa 0a [2] ed 01 [2] f6 4f [2] cb }

  condition:
    any of them
}