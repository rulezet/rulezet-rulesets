rule TTP_XOR_MULT_DOSStub_982a {
  strings:
    $key_982a = { cc 42 [2] b8 5a [2] ff 58 [2] b8 49 [2] f6 45 [2] fa 4f [2] ed 44 [2] f6 0a [2] cb }

  condition:
    any of them
}