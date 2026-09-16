rule TTP_XOR_MULT_DOSStub_81f3 {
  strings:
    $key_81f3 = { d5 9b [2] a1 83 [2] e6 81 [2] a1 90 [2] ef 9c [2] e3 96 [2] f4 9d [2] ef d3 [2] d2 }

  condition:
    any of them
}