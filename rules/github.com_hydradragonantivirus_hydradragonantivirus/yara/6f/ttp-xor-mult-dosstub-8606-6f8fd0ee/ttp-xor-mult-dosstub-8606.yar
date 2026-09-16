rule TTP_XOR_MULT_DOSStub_8606 {
  strings:
    $key_8606 = { d2 6e [2] a6 76 [2] e1 74 [2] a6 65 [2] e8 69 [2] e4 63 [2] f3 68 [2] e8 26 [2] d5 }

  condition:
    any of them
}