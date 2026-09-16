rule TTP_XOR_MULT_DOSStub_a118 {
  strings:
    $key_a118 = { f5 70 [2] 81 68 [2] c6 6a [2] 81 7b [2] cf 77 [2] c3 7d [2] d4 76 [2] cf 38 [2] f2 }

  condition:
    any of them
}