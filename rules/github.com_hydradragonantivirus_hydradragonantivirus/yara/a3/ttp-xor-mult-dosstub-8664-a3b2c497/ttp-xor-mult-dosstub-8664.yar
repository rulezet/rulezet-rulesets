rule TTP_XOR_MULT_DOSStub_8664 {
  strings:
    $key_8664 = { d2 0c [2] a6 14 [2] e1 16 [2] a6 07 [2] e8 0b [2] e4 01 [2] f3 0a [2] e8 44 [2] d5 }

  condition:
    any of them
}