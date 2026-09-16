rule TTP_XOR_MULT_DOSStub_865b {
  strings:
    $key_865b = { d2 33 [2] a6 2b [2] e1 29 [2] a6 38 [2] e8 34 [2] e4 3e [2] f3 35 [2] e8 7b [2] d5 }

  condition:
    any of them
}