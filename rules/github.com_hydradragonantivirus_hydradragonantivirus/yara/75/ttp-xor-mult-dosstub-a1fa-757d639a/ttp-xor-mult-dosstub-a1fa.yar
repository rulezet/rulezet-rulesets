rule TTP_XOR_MULT_DOSStub_a1fa {
  strings:
    $key_a1fa = { f5 92 [2] 81 8a [2] c6 88 [2] 81 99 [2] cf 95 [2] c3 9f [2] d4 94 [2] cf da [2] f2 }

  condition:
    any of them
}