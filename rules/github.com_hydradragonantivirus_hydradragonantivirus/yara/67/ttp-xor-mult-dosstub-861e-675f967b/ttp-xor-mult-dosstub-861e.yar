rule TTP_XOR_MULT_DOSStub_861e {
  strings:
    $key_861e = { d2 76 [2] a6 6e [2] e1 6c [2] a6 7d [2] e8 71 [2] e4 7b [2] f3 70 [2] e8 3e [2] d5 }

  condition:
    any of them
}