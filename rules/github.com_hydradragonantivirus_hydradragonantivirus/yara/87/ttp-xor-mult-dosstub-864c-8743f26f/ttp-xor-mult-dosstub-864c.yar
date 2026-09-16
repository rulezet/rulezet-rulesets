rule TTP_XOR_MULT_DOSStub_864c {
  strings:
    $key_864c = { d2 24 [2] a6 3c [2] e1 3e [2] a6 2f [2] e8 23 [2] e4 29 [2] f3 22 [2] e8 6c [2] d5 }

  condition:
    any of them
}