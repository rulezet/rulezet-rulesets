rule TTP_XOR_MULT_DOSStub_8163 {
  strings:
    $key_8163 = { d5 0b [2] a1 13 [2] e6 11 [2] a1 00 [2] ef 0c [2] e3 06 [2] f4 0d [2] ef 43 [2] d2 }

  condition:
    any of them
}