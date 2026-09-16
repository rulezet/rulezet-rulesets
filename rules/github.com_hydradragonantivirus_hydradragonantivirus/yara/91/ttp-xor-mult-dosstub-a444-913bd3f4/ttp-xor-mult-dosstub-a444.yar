rule TTP_XOR_MULT_DOSStub_a444 {
  strings:
    $key_a444 = { f0 2c [2] 84 34 [2] c3 36 [2] 84 27 [2] ca 2b [2] c6 21 [2] d1 2a [2] ca 64 [2] f7 }

  condition:
    any of them
}