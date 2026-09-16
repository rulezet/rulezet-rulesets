rule TTP_XOR_MULT_DOSStub_982f {
  strings:
    $key_982f = { cc 47 [2] b8 5f [2] ff 5d [2] b8 4c [2] f6 40 [2] fa 4a [2] ed 41 [2] f6 0f [2] cb }

  condition:
    any of them
}