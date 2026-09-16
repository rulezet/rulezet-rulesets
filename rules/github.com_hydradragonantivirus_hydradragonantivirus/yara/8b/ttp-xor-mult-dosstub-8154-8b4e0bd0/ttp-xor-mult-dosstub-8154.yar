rule TTP_XOR_MULT_DOSStub_8154 {
  strings:
    $key_8154 = { d5 3c [2] a1 24 [2] e6 26 [2] a1 37 [2] ef 3b [2] e3 31 [2] f4 3a [2] ef 74 [2] d2 }

  condition:
    any of them
}