rule TTP_XOR_MULT_DOSStub_a622 {
  strings:
    $key_a622 = { f2 4a [2] 86 52 [2] c1 50 [2] 86 41 [2] c8 4d [2] c4 47 [2] d3 4c [2] c8 02 [2] f5 }

  condition:
    any of them
}