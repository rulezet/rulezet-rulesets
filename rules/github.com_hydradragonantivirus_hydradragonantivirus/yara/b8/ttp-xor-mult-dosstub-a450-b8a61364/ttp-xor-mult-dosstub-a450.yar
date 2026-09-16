rule TTP_XOR_MULT_DOSStub_a450 {
  strings:
    $key_a450 = { f0 38 [2] 84 20 [2] c3 22 [2] 84 33 [2] ca 3f [2] c6 35 [2] d1 3e [2] ca 70 [2] f7 }

  condition:
    any of them
}