rule TTP_XOR_MULT_DOSStub_8138 {
  strings:
    $key_8138 = { d5 50 [2] a1 48 [2] e6 4a [2] a1 5b [2] ef 57 [2] e3 5d [2] f4 56 [2] ef 18 [2] d2 }

  condition:
    any of them
}