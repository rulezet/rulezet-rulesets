rule TTP_XOR_MULT_DOSStub_a7fa {
  strings:
    $key_a7fa = { f3 92 [2] 87 8a [2] c0 88 [2] 87 99 [2] c9 95 [2] c5 9f [2] d2 94 [2] c9 da [2] f4 }

  condition:
    any of them
}