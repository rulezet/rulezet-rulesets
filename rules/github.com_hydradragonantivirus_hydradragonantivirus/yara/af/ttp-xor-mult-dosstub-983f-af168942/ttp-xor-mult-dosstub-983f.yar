rule TTP_XOR_MULT_DOSStub_983f {
  strings:
    $key_983f = { cc 57 [2] b8 4f [2] ff 4d [2] b8 5c [2] f6 50 [2] fa 5a [2] ed 51 [2] f6 1f [2] cb }

  condition:
    any of them
}