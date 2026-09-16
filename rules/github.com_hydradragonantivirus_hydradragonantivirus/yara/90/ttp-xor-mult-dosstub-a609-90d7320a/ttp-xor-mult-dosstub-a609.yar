rule TTP_XOR_MULT_DOSStub_a609 {
  strings:
    $key_a609 = { f2 61 [2] 86 79 [2] c1 7b [2] 86 6a [2] c8 66 [2] c4 6c [2] d3 67 [2] c8 29 [2] f5 }

  condition:
    any of them
}