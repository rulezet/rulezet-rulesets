rule TTP_XOR_MULT_DOSStub_81f2 {
  strings:
    $key_81f2 = { d5 9a [2] a1 82 [2] e6 80 [2] a1 91 [2] ef 9d [2] e3 97 [2] f4 9c [2] ef d2 [2] d2 }

  condition:
    any of them
}