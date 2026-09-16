rule TTP_XOR_MULT_DOSStub_861c {
  strings:
    $key_861c = { d2 74 [2] a6 6c [2] e1 6e [2] a6 7f [2] e8 73 [2] e4 79 [2] f3 72 [2] e8 3c [2] d5 }

  condition:
    any of them
}