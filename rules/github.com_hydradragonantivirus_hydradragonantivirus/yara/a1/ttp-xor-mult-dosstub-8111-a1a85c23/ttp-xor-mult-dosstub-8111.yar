rule TTP_XOR_MULT_DOSStub_8111 {
  strings:
    $key_8111 = { d5 79 [2] a1 61 [2] e6 63 [2] a1 72 [2] ef 7e [2] e3 74 [2] f4 7f [2] ef 31 [2] d2 }

  condition:
    any of them
}