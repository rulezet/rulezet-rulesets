rule TTP_XOR_MULT_DOSStub_81f8 {
  strings:
    $key_81f8 = { d5 90 [2] a1 88 [2] e6 8a [2] a1 9b [2] ef 97 [2] e3 9d [2] f4 96 [2] ef d8 [2] d2 }

  condition:
    any of them
}