rule TTP_XOR_MULT_DOSStub_81e9 {
  strings:
    $key_81e9 = { d5 81 [2] a1 99 [2] e6 9b [2] a1 8a [2] ef 86 [2] e3 8c [2] f4 87 [2] ef c9 [2] d2 }

  condition:
    any of them
}