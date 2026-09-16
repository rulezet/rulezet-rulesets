rule TTP_XOR_MULT_DOSStub_ab07 {
  strings:
    $key_ab07 = { ff 6f [2] 8b 77 [2] cc 75 [2] 8b 64 [2] c5 68 [2] c9 62 [2] de 69 [2] c5 27 [2] f8 }

  condition:
    any of them
}