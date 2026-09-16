rule TTP_XOR_MULT_DOSStub_8662 {
  strings:
    $key_8662 = { d2 0a [2] a6 12 [2] e1 10 [2] a6 01 [2] e8 0d [2] e4 07 [2] f3 0c [2] e8 42 [2] d5 }

  condition:
    any of them
}