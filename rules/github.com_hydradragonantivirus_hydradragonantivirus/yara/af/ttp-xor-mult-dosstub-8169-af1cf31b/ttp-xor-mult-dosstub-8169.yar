rule TTP_XOR_MULT_DOSStub_8169 {
  strings:
    $key_8169 = { d5 01 [2] a1 19 [2] e6 1b [2] a1 0a [2] ef 06 [2] e3 0c [2] f4 07 [2] ef 49 [2] d2 }

  condition:
    any of them
}