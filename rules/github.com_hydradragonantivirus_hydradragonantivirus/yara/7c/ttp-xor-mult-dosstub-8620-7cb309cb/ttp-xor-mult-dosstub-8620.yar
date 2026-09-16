rule TTP_XOR_MULT_DOSStub_8620 {
  strings:
    $key_8620 = { d2 48 [2] a6 50 [2] e1 52 [2] a6 43 [2] e8 4f [2] e4 45 [2] f3 4e [2] e8 00 [2] d5 }

  condition:
    any of them
}