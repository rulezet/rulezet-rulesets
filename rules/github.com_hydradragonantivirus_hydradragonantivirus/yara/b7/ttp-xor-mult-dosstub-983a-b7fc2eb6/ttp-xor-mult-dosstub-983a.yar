rule TTP_XOR_MULT_DOSStub_983a {
  strings:
    $key_983a = { cc 52 [2] b8 4a [2] ff 48 [2] b8 59 [2] f6 55 [2] fa 5f [2] ed 54 [2] f6 1a [2] cb }

  condition:
    any of them
}