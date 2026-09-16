rule TTP_XOR_MULT_DOSStub_8145 {
  strings:
    $key_8145 = { d5 2d [2] a1 35 [2] e6 37 [2] a1 26 [2] ef 2a [2] e3 20 [2] f4 2b [2] ef 65 [2] d2 }

  condition:
    any of them
}