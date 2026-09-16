rule TTP_XOR_MULT_DOSStub_81ef {
  strings:
    $key_81ef = { d5 87 [2] a1 9f [2] e6 9d [2] a1 8c [2] ef 80 [2] e3 8a [2] f4 81 [2] ef cf [2] d2 }

  condition:
    any of them
}