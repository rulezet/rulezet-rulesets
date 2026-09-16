rule TTP_XOR_MULT_DOSStub_8779 {
  strings:
    $key_8779 = { d3 11 [2] a7 09 [2] e0 0b [2] a7 1a [2] e9 16 [2] e5 1c [2] f2 17 [2] e9 59 [2] d4 }

  condition:
    any of them
}