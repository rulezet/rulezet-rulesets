rule TTP_XOR_MULT_DOSStub_81fa {
  strings:
    $key_81fa = { d5 92 [2] a1 8a [2] e6 88 [2] a1 99 [2] ef 95 [2] e3 9f [2] f4 94 [2] ef da [2] d2 }

  condition:
    any of them
}