rule TTP_XOR_MULT_DOSStub_867d {
  strings:
    $key_867d = { d2 15 [2] a6 0d [2] e1 0f [2] a6 1e [2] e8 12 [2] e4 18 [2] f3 13 [2] e8 5d [2] d5 }

  condition:
    any of them
}