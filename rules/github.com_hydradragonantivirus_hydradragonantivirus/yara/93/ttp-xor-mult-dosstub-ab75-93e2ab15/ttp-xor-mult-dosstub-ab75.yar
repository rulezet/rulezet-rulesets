rule TTP_XOR_MULT_DOSStub_ab75 {
  strings:
    $key_ab75 = { ff 1d [2] 8b 05 [2] cc 07 [2] 8b 16 [2] c5 1a [2] c9 10 [2] de 1b [2] c5 55 [2] f8 }

  condition:
    any of them
}