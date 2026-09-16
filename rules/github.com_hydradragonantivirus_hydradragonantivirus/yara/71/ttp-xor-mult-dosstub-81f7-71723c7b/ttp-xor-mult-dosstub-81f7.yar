rule TTP_XOR_MULT_DOSStub_81f7 {
  strings:
    $key_81f7 = { d5 9f [2] a1 87 [2] e6 85 [2] a1 94 [2] ef 98 [2] e3 92 [2] f4 99 [2] ef d7 [2] d2 }

  condition:
    any of them
}