rule TTP_XOR_MULT_DOSStub_a67e {
  strings:
    $key_a67e = { f2 16 [2] 86 0e [2] c1 0c [2] 86 1d [2] c8 11 [2] c4 1b [2] d3 10 [2] c8 5e [2] f5 }

  condition:
    any of them
}