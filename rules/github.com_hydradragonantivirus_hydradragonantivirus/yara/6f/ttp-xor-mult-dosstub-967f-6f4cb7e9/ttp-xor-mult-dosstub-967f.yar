rule TTP_XOR_MULT_DOSStub_967f {
  strings:
    $key_967f = { c2 17 [2] b6 0f [2] f1 0d [2] b6 1c [2] f8 10 [2] f4 1a [2] e3 11 [2] f8 5f [2] c5 }

  condition:
    any of them
}