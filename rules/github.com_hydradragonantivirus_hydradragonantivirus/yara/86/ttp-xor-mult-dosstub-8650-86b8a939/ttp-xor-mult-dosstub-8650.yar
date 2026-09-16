rule TTP_XOR_MULT_DOSStub_8650 {
  strings:
    $key_8650 = { d2 38 [2] a6 20 [2] e1 22 [2] a6 33 [2] e8 3f [2] e4 35 [2] f3 3e [2] e8 70 [2] d5 }

  condition:
    any of them
}