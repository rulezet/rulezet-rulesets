rule TTP_XOR_MULT_DOSStub_a634 {
  strings:
    $key_a634 = { f2 5c [2] 86 44 [2] c1 46 [2] 86 57 [2] c8 5b [2] c4 51 [2] d3 5a [2] c8 14 [2] f5 }

  condition:
    any of them
}