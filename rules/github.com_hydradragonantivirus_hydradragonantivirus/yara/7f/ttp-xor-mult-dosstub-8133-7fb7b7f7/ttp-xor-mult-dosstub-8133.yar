rule TTP_XOR_MULT_DOSStub_8133 {
  strings:
    $key_8133 = { d5 5b [2] a1 43 [2] e6 41 [2] a1 50 [2] ef 5c [2] e3 56 [2] f4 5d [2] ef 13 [2] d2 }

  condition:
    any of them
}