rule TTP_XOR_MULT_DOSStub_8117 {
  strings:
    $key_8117 = { d5 7f [2] a1 67 [2] e6 65 [2] a1 74 [2] ef 78 [2] e3 72 [2] f4 79 [2] ef 37 [2] d2 }

  condition:
    any of them
}