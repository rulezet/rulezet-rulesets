rule TTP_XOR_MULT_DOSStub_8730 {
  strings:
    $key_8730 = { d3 58 [2] a7 40 [2] e0 42 [2] a7 53 [2] e9 5f [2] e5 55 [2] f2 5e [2] e9 10 [2] d4 }

  condition:
    any of them
}