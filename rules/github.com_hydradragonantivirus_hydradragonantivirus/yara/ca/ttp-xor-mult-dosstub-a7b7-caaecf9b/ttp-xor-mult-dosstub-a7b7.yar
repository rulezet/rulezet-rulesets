rule TTP_XOR_MULT_DOSStub_a7b7 {
  strings:
    $key_a7b7 = { f3 df [2] 87 c7 [2] c0 c5 [2] 87 d4 [2] c9 d8 [2] c5 d2 [2] d2 d9 [2] c9 97 [2] f4 }

  condition:
    any of them
}