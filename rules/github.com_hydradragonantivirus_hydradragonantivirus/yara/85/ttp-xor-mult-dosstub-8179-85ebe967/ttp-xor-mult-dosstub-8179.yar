rule TTP_XOR_MULT_DOSStub_8179 {
  strings:
    $key_8179 = { d5 11 [2] a1 09 [2] e6 0b [2] a1 1a [2] ef 16 [2] e3 1c [2] f4 17 [2] ef 59 [2] d2 }

  condition:
    any of them
}