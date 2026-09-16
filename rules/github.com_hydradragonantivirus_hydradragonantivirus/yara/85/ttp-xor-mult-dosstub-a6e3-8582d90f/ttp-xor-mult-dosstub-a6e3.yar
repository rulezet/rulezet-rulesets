rule TTP_XOR_MULT_DOSStub_a6e3 {
  strings:
    $key_a6e3 = { f2 8b [2] 86 93 [2] c1 91 [2] 86 80 [2] c8 8c [2] c4 86 [2] d3 8d [2] c8 c3 [2] f5 }

  condition:
    any of them
}