rule TTP_XOR_MULT_DOSStub_ab37 {
  strings:
    $key_ab37 = { ff 5f [2] 8b 47 [2] cc 45 [2] 8b 54 [2] c5 58 [2] c9 52 [2] de 59 [2] c5 17 [2] f8 }

  condition:
    any of them
}