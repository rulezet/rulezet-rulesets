rule TTP_XOR_MULT_DOSStub_980f {
  strings:
    $key_980f = { cc 67 [2] b8 7f [2] ff 7d [2] b8 6c [2] f6 60 [2] fa 6a [2] ed 61 [2] f6 2f [2] cb }

  condition:
    any of them
}