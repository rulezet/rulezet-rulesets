rule TTP_XOR_MULT_DOSStub_a6e5 {
  strings:
    $key_a6e5 = { f2 8d [2] 86 95 [2] c1 97 [2] 86 86 [2] c8 8a [2] c4 80 [2] d3 8b [2] c8 c5 [2] f5 }

  condition:
    any of them
}