rule TTP_XOR_MULT_DOSStub_a674 {
  strings:
    $key_a674 = { f2 1c [2] 86 04 [2] c1 06 [2] 86 17 [2] c8 1b [2] c4 11 [2] d3 1a [2] c8 54 [2] f5 }

  condition:
    any of them
}