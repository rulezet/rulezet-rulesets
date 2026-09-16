rule TTP_XOR_MULT_DOSStub_8178 {
  strings:
    $key_8178 = { d5 10 [2] a1 08 [2] e6 0a [2] a1 1b [2] ef 17 [2] e3 1d [2] f4 16 [2] ef 58 [2] d2 }

  condition:
    any of them
}