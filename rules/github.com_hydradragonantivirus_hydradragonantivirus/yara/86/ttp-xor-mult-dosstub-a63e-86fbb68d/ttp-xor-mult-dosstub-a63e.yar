rule TTP_XOR_MULT_DOSStub_a63e {
  strings:
    $key_a63e = { f2 56 [2] 86 4e [2] c1 4c [2] 86 5d [2] c8 51 [2] c4 5b [2] d3 50 [2] c8 1e [2] f5 }

  condition:
    any of them
}