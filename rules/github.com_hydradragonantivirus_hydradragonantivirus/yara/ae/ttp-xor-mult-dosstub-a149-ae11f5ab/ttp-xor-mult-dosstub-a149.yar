rule TTP_XOR_MULT_DOSStub_a149 {
  strings:
    $key_a149 = { f5 21 [2] 81 39 [2] c6 3b [2] 81 2a [2] cf 26 [2] c3 2c [2] d4 27 [2] cf 69 [2] f2 }

  condition:
    any of them
}