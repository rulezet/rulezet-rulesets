rule TTP_XOR_MULT_DOSStub_8642 {
  strings:
    $key_8642 = { d2 2a [2] a6 32 [2] e1 30 [2] a6 21 [2] e8 2d [2] e4 27 [2] f3 2c [2] e8 62 [2] d5 }

  condition:
    any of them
}