rule TTP_XOR_MULT_DOSStub_81e2 {
  strings:
    $key_81e2 = { d5 8a [2] a1 92 [2] e6 90 [2] a1 81 [2] ef 8d [2] e3 87 [2] f4 8c [2] ef c2 [2] d2 }

  condition:
    any of them
}