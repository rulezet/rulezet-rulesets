rule TTP_XOR_MULT_DOSStub_864d {
  strings:
    $key_864d = { d2 25 [2] a6 3d [2] e1 3f [2] a6 2e [2] e8 22 [2] e4 28 [2] f3 23 [2] e8 6d [2] d5 }

  condition:
    any of them
}