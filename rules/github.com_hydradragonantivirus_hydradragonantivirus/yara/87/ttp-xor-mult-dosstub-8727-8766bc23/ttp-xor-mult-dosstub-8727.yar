rule TTP_XOR_MULT_DOSStub_8727 {
  strings:
    $key_8727 = { d3 4f [2] a7 57 [2] e0 55 [2] a7 44 [2] e9 48 [2] e5 42 [2] f2 49 [2] e9 07 [2] d4 }

  condition:
    any of them
}