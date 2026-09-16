rule TTP_XOR_MULT_DOSStub_8600 {
  strings:
    $key_8600 = { d2 68 [2] a6 70 [2] e1 72 [2] a6 63 [2] e8 6f [2] e4 65 [2] f3 6e [2] e8 20 [2] d5 }

  condition:
    any of them
}