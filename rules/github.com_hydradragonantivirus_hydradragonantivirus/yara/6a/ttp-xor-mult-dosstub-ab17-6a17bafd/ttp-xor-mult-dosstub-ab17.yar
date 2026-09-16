rule TTP_XOR_MULT_DOSStub_ab17 {
  strings:
    $key_ab17 = { ff 7f [2] 8b 67 [2] cc 65 [2] 8b 74 [2] c5 78 [2] c9 72 [2] de 79 [2] c5 37 [2] f8 }

  condition:
    any of them
}