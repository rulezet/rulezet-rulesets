rule TTP_XOR_MULT_DOSStub_8658 {
  strings:
    $key_8658 = { d2 30 [2] a6 28 [2] e1 2a [2] a6 3b [2] e8 37 [2] e4 3d [2] f3 36 [2] e8 78 [2] d5 }

  condition:
    any of them
}