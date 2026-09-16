rule TTP_XOR_MULT_DOSStub_8636 {
  strings:
    $key_8636 = { d2 5e [2] a6 46 [2] e1 44 [2] a6 55 [2] e8 59 [2] e4 53 [2] f3 58 [2] e8 16 [2] d5 }

  condition:
    any of them
}