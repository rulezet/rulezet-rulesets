rule TTP_XOR_MULT_DOSStub_81e1 {
  strings:
    $key_81e1 = { d5 89 [2] a1 91 [2] e6 93 [2] a1 82 [2] ef 8e [2] e3 84 [2] f4 8f [2] ef c1 [2] d2 }

  condition:
    any of them
}