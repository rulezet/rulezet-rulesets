rule TTP_XOR_MULT_DOSStub_a639 {
  strings:
    $key_a639 = { f2 51 [2] 86 49 [2] c1 4b [2] 86 5a [2] c8 56 [2] c4 5c [2] d3 57 [2] c8 19 [2] f5 }

  condition:
    any of them
}