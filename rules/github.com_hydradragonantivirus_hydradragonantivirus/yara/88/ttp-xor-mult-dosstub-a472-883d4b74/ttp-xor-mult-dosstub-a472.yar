rule TTP_XOR_MULT_DOSStub_a472 {
  strings:
    $key_a472 = { f0 1a [2] 84 02 [2] c3 00 [2] 84 11 [2] ca 1d [2] c6 17 [2] d1 1c [2] ca 52 [2] f7 }

  condition:
    any of them
}