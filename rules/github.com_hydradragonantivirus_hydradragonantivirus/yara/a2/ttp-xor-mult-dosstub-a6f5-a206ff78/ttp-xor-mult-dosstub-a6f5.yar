rule TTP_XOR_MULT_DOSStub_a6f5 {
  strings:
    $key_a6f5 = { f2 9d [2] 86 85 [2] c1 87 [2] 86 96 [2] c8 9a [2] c4 90 [2] d3 9b [2] c8 d5 [2] f5 }

  condition:
    any of them
}