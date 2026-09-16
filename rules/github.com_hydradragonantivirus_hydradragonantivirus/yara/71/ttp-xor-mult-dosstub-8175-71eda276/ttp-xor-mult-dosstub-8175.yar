rule TTP_XOR_MULT_DOSStub_8175 {
  strings:
    $key_8175 = { d5 1d [2] a1 05 [2] e6 07 [2] a1 16 [2] ef 1a [2] e3 10 [2] f4 1b [2] ef 55 [2] d2 }

  condition:
    any of them
}