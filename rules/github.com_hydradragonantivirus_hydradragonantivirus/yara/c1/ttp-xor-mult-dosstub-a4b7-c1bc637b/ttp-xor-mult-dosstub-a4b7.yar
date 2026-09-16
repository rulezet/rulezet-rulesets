rule TTP_XOR_MULT_DOSStub_a4b7 {
  strings:
    $key_a4b7 = { f0 df [2] 84 c7 [2] c3 c5 [2] 84 d4 [2] ca d8 [2] c6 d2 [2] d1 d9 [2] ca 97 [2] f7 }

  condition:
    any of them
}