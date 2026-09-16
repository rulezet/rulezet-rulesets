rule TTP_XOR_MULT_DOSStub_8157 {
  strings:
    $key_8157 = { d5 3f [2] a1 27 [2] e6 25 [2] a1 34 [2] ef 38 [2] e3 32 [2] f4 39 [2] ef 77 [2] d2 }

  condition:
    any of them
}