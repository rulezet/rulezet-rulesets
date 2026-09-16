rule TTP_XOR_MULT_DOSStub_8760 {
  strings:
    $key_8760 = { d3 08 [2] a7 10 [2] e0 12 [2] a7 03 [2] e9 0f [2] e5 05 [2] f2 0e [2] e9 40 [2] d4 }

  condition:
    any of them
}