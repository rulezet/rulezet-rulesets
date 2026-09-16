rule TTP_XOR_MULT_DOSStub_8136 {
  strings:
    $key_8136 = { d5 5e [2] a1 46 [2] e6 44 [2] a1 55 [2] ef 59 [2] e3 53 [2] f4 58 [2] ef 16 [2] d2 }

  condition:
    any of them
}