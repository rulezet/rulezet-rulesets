rule TTP_XOR_MULT_DOSStub_ab00 {
  strings:
    $key_ab00 = { ff 68 [2] 8b 70 [2] cc 72 [2] 8b 63 [2] c5 6f [2] c9 65 [2] de 6e [2] c5 20 [2] f8 }

  condition:
    any of them
}