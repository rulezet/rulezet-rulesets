rule TTP_XOR_MULT_DOSStub_a648 {
  strings:
    $key_a648 = { f2 20 [2] 86 38 [2] c1 3a [2] 86 2b [2] c8 27 [2] c4 2d [2] d3 26 [2] c8 68 [2] f5 }

  condition:
    any of them
}