rule TTP_XOR_MULT_DOSStub_8174 {
  strings:
    $key_8174 = { d5 1c [2] a1 04 [2] e6 06 [2] a1 17 [2] ef 1b [2] e3 11 [2] f4 1a [2] ef 54 [2] d2 }

  condition:
    any of them
}