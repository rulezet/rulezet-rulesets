rule TTP_XOR_MULT_DOSStub_8115 {
  strings:
    $key_8115 = { d5 7d [2] a1 65 [2] e6 67 [2] a1 76 [2] ef 7a [2] e3 70 [2] f4 7b [2] ef 35 [2] d2 }

  condition:
    any of them
}