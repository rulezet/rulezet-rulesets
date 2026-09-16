rule TTP_XOR_MULT_DOSStub_a477 {
  strings:
    $key_a477 = { f0 1f [2] 84 07 [2] c3 05 [2] 84 14 [2] ca 18 [2] c6 12 [2] d1 19 [2] ca 57 [2] f7 }

  condition:
    any of them
}