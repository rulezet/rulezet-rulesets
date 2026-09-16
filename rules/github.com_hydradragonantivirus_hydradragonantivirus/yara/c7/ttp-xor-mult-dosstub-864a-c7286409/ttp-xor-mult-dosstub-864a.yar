rule TTP_XOR_MULT_DOSStub_864a {
  strings:
    $key_864a = { d2 22 [2] a6 3a [2] e1 38 [2] a6 29 [2] e8 25 [2] e4 2f [2] f3 24 [2] e8 6a [2] d5 }

  condition:
    any of them
}