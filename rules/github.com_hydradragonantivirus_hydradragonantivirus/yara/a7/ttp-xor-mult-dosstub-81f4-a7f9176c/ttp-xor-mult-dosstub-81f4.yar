rule TTP_XOR_MULT_DOSStub_81f4 {
  strings:
    $key_81f4 = { d5 9c [2] a1 84 [2] e6 86 [2] a1 97 [2] ef 9b [2] e3 91 [2] f4 9a [2] ef d4 [2] d2 }

  condition:
    any of them
}