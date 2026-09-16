rule TTP_XOR_MULT_DOSStub_a62e {
  strings:
    $key_a62e = { f2 46 [2] 86 5e [2] c1 5c [2] 86 4d [2] c8 41 [2] c4 4b [2] d3 40 [2] c8 0e [2] f5 }

  condition:
    any of them
}