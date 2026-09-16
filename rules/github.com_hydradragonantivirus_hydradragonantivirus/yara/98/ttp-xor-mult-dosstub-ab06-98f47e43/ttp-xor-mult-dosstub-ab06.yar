rule TTP_XOR_MULT_DOSStub_ab06 {
  strings:
    $key_ab06 = { ff 6e [2] 8b 76 [2] cc 74 [2] 8b 65 [2] c5 69 [2] c9 63 [2] de 68 [2] c5 26 [2] f8 }

  condition:
    any of them
}