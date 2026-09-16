rule TTP_XOR_MULT_DOSStub_8168 {
  strings:
    $key_8168 = { d5 00 [2] a1 18 [2] e6 1a [2] a1 0b [2] ef 07 [2] e3 0d [2] f4 06 [2] ef 48 [2] d2 }

  condition:
    any of them
}