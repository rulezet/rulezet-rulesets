rule TTP_XOR_MULT_DOSStub_8720 {
  strings:
    $key_8720 = { d3 48 [2] a7 50 [2] e0 52 [2] a7 43 [2] e9 4f [2] e5 45 [2] f2 4e [2] e9 00 [2] d4 }

  condition:
    any of them
}