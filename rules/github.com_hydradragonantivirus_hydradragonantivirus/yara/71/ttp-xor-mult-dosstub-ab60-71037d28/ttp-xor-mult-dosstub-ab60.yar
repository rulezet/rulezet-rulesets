rule TTP_XOR_MULT_DOSStub_ab60 {
  strings:
    $key_ab60 = { ff 08 [2] 8b 10 [2] cc 12 [2] 8b 03 [2] c5 0f [2] c9 05 [2] de 0e [2] c5 40 [2] f8 }

  condition:
    any of them
}