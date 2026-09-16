rule TTP_XOR_MULT_DOSStub_865a {
  strings:
    $key_865a = { d2 32 [2] a6 2a [2] e1 28 [2] a6 39 [2] e8 35 [2] e4 3f [2] f3 34 [2] e8 7a [2] d5 }

  condition:
    any of them
}