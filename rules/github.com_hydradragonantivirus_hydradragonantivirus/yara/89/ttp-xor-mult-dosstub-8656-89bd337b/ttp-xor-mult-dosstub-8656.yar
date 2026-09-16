rule TTP_XOR_MULT_DOSStub_8656 {
  strings:
    $key_8656 = { d2 3e [2] a6 26 [2] e1 24 [2] a6 35 [2] e8 39 [2] e4 33 [2] f3 38 [2] e8 76 [2] d5 }

  condition:
    any of them
}