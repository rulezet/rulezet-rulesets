rule TTP_XOR_MULT_DOSStub_8160 {
  strings:
    $key_8160 = { d5 08 [2] a1 10 [2] e6 12 [2] a1 03 [2] ef 0f [2] e3 05 [2] f4 0e [2] ef 40 [2] d2 }

  condition:
    any of them
}