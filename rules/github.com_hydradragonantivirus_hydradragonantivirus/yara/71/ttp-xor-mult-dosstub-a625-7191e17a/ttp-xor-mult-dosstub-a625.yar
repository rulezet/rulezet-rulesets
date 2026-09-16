rule TTP_XOR_MULT_DOSStub_a625 {
  strings:
    $key_a625 = { f2 4d [2] 86 55 [2] c1 57 [2] 86 46 [2] c8 4a [2] c4 40 [2] d3 4b [2] c8 05 [2] f5 }

  condition:
    any of them
}