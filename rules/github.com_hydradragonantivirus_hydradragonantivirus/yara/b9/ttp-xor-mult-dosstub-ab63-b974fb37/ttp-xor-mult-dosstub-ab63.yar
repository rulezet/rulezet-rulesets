rule TTP_XOR_MULT_DOSStub_ab63 {
  strings:
    $key_ab63 = { ff 0b [2] 8b 13 [2] cc 11 [2] 8b 00 [2] c5 0c [2] c9 06 [2] de 0d [2] c5 43 [2] f8 }

  condition:
    any of them
}