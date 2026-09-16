rule TTP_XOR_MULT_DOSStub_8763 {
  strings:
    $key_8763 = { d3 0b [2] a7 13 [2] e0 11 [2] a7 00 [2] e9 0c [2] e5 06 [2] f2 0d [2] e9 43 [2] d4 }

  condition:
    any of them
}