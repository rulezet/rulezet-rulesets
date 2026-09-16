rule TTP_XOR_MULT_DOSStub_a663 {
  strings:
    $key_a663 = { f2 0b [2] 86 13 [2] c1 11 [2] 86 00 [2] c8 0c [2] c4 06 [2] d3 0d [2] c8 43 [2] f5 }

  condition:
    any of them
}