rule TTP_XOR_MULT_DOSStub_a138 {
  strings:
    $key_a138 = { f5 50 [2] 81 48 [2] c6 4a [2] 81 5b [2] cf 57 [2] c3 5d [2] d4 56 [2] cf 18 [2] f2 }

  condition:
    any of them
}