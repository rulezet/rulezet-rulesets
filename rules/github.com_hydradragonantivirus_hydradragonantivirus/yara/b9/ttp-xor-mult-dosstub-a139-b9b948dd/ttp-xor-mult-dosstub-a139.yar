rule TTP_XOR_MULT_DOSStub_a139 {
  strings:
    $key_a139 = { f5 51 [2] 81 49 [2] c6 4b [2] 81 5a [2] cf 56 [2] c3 5c [2] d4 57 [2] cf 19 [2] f2 }

  condition:
    any of them
}