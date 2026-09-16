rule TTP_XOR_MULT_DOSStub_8772 {
  strings:
    $key_8772 = { d3 1a [2] a7 02 [2] e0 00 [2] a7 11 [2] e9 1d [2] e5 17 [2] f2 1c [2] e9 52 [2] d4 }

  condition:
    any of them
}