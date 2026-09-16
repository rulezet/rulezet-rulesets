rule TTP_XOR_MULT_DOSStub_ab36 {
  strings:
    $key_ab36 = { ff 5e [2] 8b 46 [2] cc 44 [2] 8b 55 [2] c5 59 [2] c9 53 [2] de 58 [2] c5 16 [2] f8 }

  condition:
    any of them
}