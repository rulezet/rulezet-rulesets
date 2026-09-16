rule TTP_XOR_MULT_DOSStub_81e4 {
  strings:
    $key_81e4 = { d5 8c [2] a1 94 [2] e6 96 [2] a1 87 [2] ef 8b [2] e3 81 [2] f4 8a [2] ef c4 [2] d2 }

  condition:
    any of them
}