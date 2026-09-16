rule TTP_XOR_MULT_DOSStub_8615 {
  strings:
    $key_8615 = { d2 7d [2] a6 65 [2] e1 67 [2] a6 76 [2] e8 7a [2] e4 70 [2] f3 7b [2] e8 35 [2] d5 }

  condition:
    any of them
}