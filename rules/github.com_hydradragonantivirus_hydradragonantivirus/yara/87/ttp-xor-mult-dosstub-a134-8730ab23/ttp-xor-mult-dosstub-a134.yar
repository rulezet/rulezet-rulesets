rule TTP_XOR_MULT_DOSStub_a134 {
  strings:
    $key_a134 = { f5 5c [2] 81 44 [2] c6 46 [2] 81 57 [2] cf 5b [2] c3 51 [2] d4 5a [2] cf 14 [2] f2 }

  condition:
    any of them
}