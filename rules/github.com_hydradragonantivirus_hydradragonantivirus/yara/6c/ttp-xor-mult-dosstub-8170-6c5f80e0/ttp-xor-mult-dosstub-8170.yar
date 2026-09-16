rule TTP_XOR_MULT_DOSStub_8170 {
  strings:
    $key_8170 = { d5 18 [2] a1 00 [2] e6 02 [2] a1 13 [2] ef 1f [2] e3 15 [2] f4 1e [2] ef 50 [2] d2 }

  condition:
    any of them
}