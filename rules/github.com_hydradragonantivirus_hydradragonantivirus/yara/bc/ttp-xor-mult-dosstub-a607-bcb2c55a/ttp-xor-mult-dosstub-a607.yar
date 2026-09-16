rule TTP_XOR_MULT_DOSStub_a607 {
  strings:
    $key_a607 = { f2 6f [2] 86 77 [2] c1 75 [2] 86 64 [2] c8 68 [2] c4 62 [2] d3 69 [2] c8 27 [2] f5 }

  condition:
    any of them
}