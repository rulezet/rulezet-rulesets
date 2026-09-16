rule TTP_XOR_MULT_DOSStub_81f9 {
  strings:
    $key_81f9 = { d5 91 [2] a1 89 [2] e6 8b [2] a1 9a [2] ef 96 [2] e3 9c [2] f4 97 [2] ef d9 [2] d2 }

  condition:
    any of them
}