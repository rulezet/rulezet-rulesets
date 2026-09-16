rule TTP_XOR_MULT_DOSStub_8549 {
  strings:
    $key_8549 = { d1 21 [2] a5 39 [2] e2 3b [2] a5 2a [2] eb 26 [2] e7 2c [2] f0 27 [2] eb 69 [2] d6 }

  condition:
    any of them
}