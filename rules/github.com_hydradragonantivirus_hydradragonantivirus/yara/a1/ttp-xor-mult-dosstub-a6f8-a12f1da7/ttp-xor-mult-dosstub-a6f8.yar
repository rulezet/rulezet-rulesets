rule TTP_XOR_MULT_DOSStub_a6f8 {
  strings:
    $key_a6f8 = { f2 90 [2] 86 88 [2] c1 8a [2] 86 9b [2] c8 97 [2] c4 9d [2] d3 96 [2] c8 d8 [2] f5 }

  condition:
    any of them
}