rule TTP_XOR_MULT_DOSStub_a637 {
  strings:
    $key_a637 = { f2 5f [2] 86 47 [2] c1 45 [2] 86 54 [2] c8 58 [2] c4 52 [2] d3 59 [2] c8 17 [2] f5 }

  condition:
    any of them
}