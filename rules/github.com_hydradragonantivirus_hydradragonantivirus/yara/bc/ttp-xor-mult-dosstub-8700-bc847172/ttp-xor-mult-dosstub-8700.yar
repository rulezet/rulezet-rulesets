rule TTP_XOR_MULT_DOSStub_8700 {
  strings:
    $key_8700 = { d3 68 [2] a7 70 [2] e0 72 [2] a7 63 [2] e9 6f [2] e5 65 [2] f2 6e [2] e9 20 [2] d4 }

  condition:
    any of them
}