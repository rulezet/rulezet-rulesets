rule TTP_XOR_MULT_DOSStub_ab70 {
  strings:
    $key_ab70 = { ff 18 [2] 8b 00 [2] cc 02 [2] 8b 13 [2] c5 1f [2] c9 15 [2] de 1e [2] c5 50 [2] f8 }

  condition:
    any of them
}