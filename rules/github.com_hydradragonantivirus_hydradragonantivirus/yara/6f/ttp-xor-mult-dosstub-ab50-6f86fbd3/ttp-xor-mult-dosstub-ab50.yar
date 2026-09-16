rule TTP_XOR_MULT_DOSStub_ab50 {
  strings:
    $key_ab50 = { ff 38 [2] 8b 20 [2] cc 22 [2] 8b 33 [2] c5 3f [2] c9 35 [2] de 3e [2] c5 70 [2] f8 }

  condition:
    any of them
}