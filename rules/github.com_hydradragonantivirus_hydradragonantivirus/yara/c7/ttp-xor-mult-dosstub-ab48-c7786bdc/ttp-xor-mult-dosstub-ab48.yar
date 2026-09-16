rule TTP_XOR_MULT_DOSStub_ab48 {
  strings:
    $key_ab48 = { ff 20 [2] 8b 38 [2] cc 3a [2] 8b 2b [2] c5 27 [2] c9 2d [2] de 26 [2] c5 68 [2] f8 }

  condition:
    any of them
}