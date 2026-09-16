rule TTP_XOR_MULT_DOSStub_8349 {
  strings:
    $key_8349 = { d7 21 [2] a3 39 [2] e4 3b [2] a3 2a [2] ed 26 [2] e1 2c [2] f6 27 [2] ed 69 [2] d0 }

  condition:
    any of them
}