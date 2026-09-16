rule TTP_XOR_MULT_DOSStub_a159 {
  strings:
    $key_a159 = { f5 31 [2] 81 29 [2] c6 2b [2] 81 3a [2] cf 36 [2] c3 3c [2] d4 37 [2] cf 79 [2] f2 }

  condition:
    any of them
}