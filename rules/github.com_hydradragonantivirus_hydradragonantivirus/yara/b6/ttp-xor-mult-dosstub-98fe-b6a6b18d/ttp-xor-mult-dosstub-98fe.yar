rule TTP_XOR_MULT_DOSStub_98fe {
  strings:
    $key_98fe = { cc 96 [2] b8 8e [2] ff 8c [2] b8 9d [2] f6 91 [2] fa 9b [2] ed 90 [2] f6 de [2] cb }

  condition:
    any of them
}