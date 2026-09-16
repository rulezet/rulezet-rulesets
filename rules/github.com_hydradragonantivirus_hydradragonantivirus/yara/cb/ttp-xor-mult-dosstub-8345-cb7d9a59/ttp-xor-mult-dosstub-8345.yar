rule TTP_XOR_MULT_DOSStub_8345 {
  strings:
    $key_8345 = { d7 2d [2] a3 35 [2] e4 37 [2] a3 26 [2] ed 2a [2] e1 20 [2] f6 2b [2] ed 65 [2] d0 }

  condition:
    any of them
}