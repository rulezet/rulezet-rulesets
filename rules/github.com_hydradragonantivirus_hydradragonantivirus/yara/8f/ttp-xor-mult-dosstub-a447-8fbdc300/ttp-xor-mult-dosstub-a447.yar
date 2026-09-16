rule TTP_XOR_MULT_DOSStub_a447 {
  strings:
    $key_a447 = { f0 2f [2] 84 37 [2] c3 35 [2] 84 24 [2] ca 28 [2] c6 22 [2] d1 29 [2] ca 67 [2] f7 }

  condition:
    any of them
}