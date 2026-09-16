rule TTP_XOR_MULT_DOSStub_ab42 {
  strings:
    $key_ab42 = { ff 2a [2] 8b 32 [2] cc 30 [2] 8b 21 [2] c5 2d [2] c9 27 [2] de 2c [2] c5 62 [2] f8 }

  condition:
    any of them
}