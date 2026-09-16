rule TTP_XOR_MULT_DOSStub_a7e4 {
  strings:
    $key_a7e4 = { f3 8c [2] 87 94 [2] c0 96 [2] 87 87 [2] c9 8b [2] c5 81 [2] d2 8a [2] c9 c4 [2] f4 }

  condition:
    any of them
}