rule TTP_XOR_MULT_DOSStub_861a {
  strings:
    $key_861a = { d2 72 [2] a6 6a [2] e1 68 [2] a6 79 [2] e8 75 [2] e4 7f [2] f3 74 [2] e8 3a [2] d5 }

  condition:
    any of them
}