rule TTP_XOR_MULT_DOSStub_aeb7 {
  strings:
    $key_aeb7 = { fa df [2] 8e c7 [2] c9 c5 [2] 8e d4 [2] c0 d8 [2] cc d2 [2] db d9 [2] c0 97 [2] fd }

  condition:
    any of them
}