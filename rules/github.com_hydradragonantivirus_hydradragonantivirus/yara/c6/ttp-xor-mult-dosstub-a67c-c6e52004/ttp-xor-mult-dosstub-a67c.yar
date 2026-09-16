rule TTP_XOR_MULT_DOSStub_a67c {
  strings:
    $key_a67c = { f2 14 [2] 86 0c [2] c1 0e [2] 86 1f [2] c8 13 [2] c4 19 [2] d3 12 [2] c8 5c [2] f5 }

  condition:
    any of them
}