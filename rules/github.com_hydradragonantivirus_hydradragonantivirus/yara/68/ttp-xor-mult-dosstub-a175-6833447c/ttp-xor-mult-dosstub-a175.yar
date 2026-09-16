rule TTP_XOR_MULT_DOSStub_a175 {
  strings:
    $key_a175 = { f5 1d [2] 81 05 [2] c6 07 [2] 81 16 [2] cf 1a [2] c3 10 [2] d4 1b [2] cf 55 [2] f2 }

  condition:
    any of them
}