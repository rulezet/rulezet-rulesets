rule TTP_XOR_MULT_DOSStub_ab65 {
  strings:
    $key_ab65 = { ff 0d [2] 8b 15 [2] cc 17 [2] 8b 06 [2] c5 0a [2] c9 00 [2] de 0b [2] c5 45 [2] f8 }

  condition:
    any of them
}