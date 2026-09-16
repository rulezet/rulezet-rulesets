rule TTP_XOR_MULT_DOSStub_ab57 {
  strings:
    $key_ab57 = { ff 3f [2] 8b 27 [2] cc 25 [2] 8b 34 [2] c5 38 [2] c9 32 [2] de 39 [2] c5 77 [2] f8 }

  condition:
    any of them
}