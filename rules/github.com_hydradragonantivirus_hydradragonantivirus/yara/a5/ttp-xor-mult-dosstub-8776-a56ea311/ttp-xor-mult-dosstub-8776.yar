rule TTP_XOR_MULT_DOSStub_8776 {
  strings:
    $key_8776 = { d3 1e [2] a7 06 [2] e0 04 [2] a7 15 [2] e9 19 [2] e5 13 [2] f2 18 [2] e9 56 [2] d4 }

  condition:
    any of them
}