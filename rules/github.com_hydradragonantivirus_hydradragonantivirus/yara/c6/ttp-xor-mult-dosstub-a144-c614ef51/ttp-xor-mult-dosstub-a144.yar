rule TTP_XOR_MULT_DOSStub_a144 {
  strings:
    $key_a144 = { f5 2c [2] 81 34 [2] c6 36 [2] 81 27 [2] cf 2b [2] c3 21 [2] d4 2a [2] cf 64 [2] f2 }

  condition:
    any of them
}