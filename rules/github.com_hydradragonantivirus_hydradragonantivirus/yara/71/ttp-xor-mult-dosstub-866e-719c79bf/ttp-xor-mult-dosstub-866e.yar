rule TTP_XOR_MULT_DOSStub_866e {
  strings:
    $key_866e = { d2 06 [2] a6 1e [2] e1 1c [2] a6 0d [2] e8 01 [2] e4 0b [2] f3 00 [2] e8 4e [2] d5 }

  condition:
    any of them
}