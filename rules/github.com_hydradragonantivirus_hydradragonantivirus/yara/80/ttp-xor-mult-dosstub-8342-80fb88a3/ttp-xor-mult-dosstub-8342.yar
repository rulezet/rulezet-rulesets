rule TTP_XOR_MULT_DOSStub_8342 {
  strings:
    $key_8342 = { d7 2a [2] a3 32 [2] e4 30 [2] a3 21 [2] ed 2d [2] e1 27 [2] f6 2c [2] ed 62 [2] d0 }

  condition:
    any of them
}