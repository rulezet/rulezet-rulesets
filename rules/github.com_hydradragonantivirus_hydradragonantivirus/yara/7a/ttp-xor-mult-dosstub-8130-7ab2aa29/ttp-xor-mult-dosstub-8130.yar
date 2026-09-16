rule TTP_XOR_MULT_DOSStub_8130 {
  strings:
    $key_8130 = { d5 58 [2] a1 40 [2] e6 42 [2] a1 53 [2] ef 5f [2] e3 55 [2] f4 5e [2] ef 10 [2] d2 }

  condition:
    any of them
}