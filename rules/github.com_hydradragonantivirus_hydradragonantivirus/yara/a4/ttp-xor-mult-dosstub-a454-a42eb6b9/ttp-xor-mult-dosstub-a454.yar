rule TTP_XOR_MULT_DOSStub_a454 {
  strings:
    $key_a454 = { f0 3c [2] 84 24 [2] c3 26 [2] 84 37 [2] ca 3b [2] c6 31 [2] d1 3a [2] ca 74 [2] f7 }

  condition:
    any of them
}