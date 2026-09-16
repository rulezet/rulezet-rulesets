rule TTP_XOR_MULT_DOSStub_81f5 {
  strings:
    $key_81f5 = { d5 9d [2] a1 85 [2] e6 87 [2] a1 96 [2] ef 9a [2] e3 90 [2] f4 9b [2] ef d5 [2] d2 }

  condition:
    any of them
}