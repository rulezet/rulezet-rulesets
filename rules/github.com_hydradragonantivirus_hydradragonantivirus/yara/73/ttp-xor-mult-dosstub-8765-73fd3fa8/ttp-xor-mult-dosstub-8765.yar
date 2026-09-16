rule TTP_XOR_MULT_DOSStub_8765 {
  strings:
    $key_8765 = { d3 0d [2] a7 15 [2] e0 17 [2] a7 06 [2] e9 0a [2] e5 00 [2] f2 0b [2] e9 45 [2] d4 }

  condition:
    any of them
}