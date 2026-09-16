rule TTP_XOR_MULT_DOSStub_ab46 {
  strings:
    $key_ab46 = { ff 2e [2] 8b 36 [2] cc 34 [2] 8b 25 [2] c5 29 [2] c9 23 [2] de 28 [2] c5 66 [2] f8 }

  condition:
    any of them
}