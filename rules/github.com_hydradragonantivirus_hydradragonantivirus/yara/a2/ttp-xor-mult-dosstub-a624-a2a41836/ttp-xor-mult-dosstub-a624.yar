rule TTP_XOR_MULT_DOSStub_a624 {
  strings:
    $key_a624 = { f2 4c [2] 86 54 [2] c1 56 [2] 86 47 [2] c8 4b [2] c4 41 [2] d3 4a [2] c8 04 [2] f5 }

  condition:
    any of them
}