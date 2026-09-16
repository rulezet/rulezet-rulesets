rule TTP_XOR_MULT_DOSStub_813d {
  strings:
    $key_813d = { d5 55 [2] a1 4d [2] e6 4f [2] a1 5e [2] ef 52 [2] e3 58 [2] f4 53 [2] ef 1d [2] d2 }

  condition:
    any of them
}