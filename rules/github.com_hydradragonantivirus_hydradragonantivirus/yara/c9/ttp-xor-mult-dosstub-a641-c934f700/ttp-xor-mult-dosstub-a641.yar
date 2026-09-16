rule TTP_XOR_MULT_DOSStub_a641 {
  strings:
    $key_a641 = { f2 29 [2] 86 31 [2] c1 33 [2] 86 22 [2] c8 2e [2] c4 24 [2] d3 2f [2] c8 61 [2] f5 }

  condition:
    any of them
}