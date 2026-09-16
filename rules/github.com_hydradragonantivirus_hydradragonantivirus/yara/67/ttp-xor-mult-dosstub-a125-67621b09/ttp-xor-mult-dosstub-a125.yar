rule TTP_XOR_MULT_DOSStub_a125 {
  strings:
    $key_a125 = { f5 4d [2] 81 55 [2] c6 57 [2] 81 46 [2] cf 4a [2] c3 40 [2] d4 4b [2] cf 05 [2] f2 }

  condition:
    any of them
}