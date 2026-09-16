rule TTP_XOR_MULT_DOSStub_ab34 {
  strings:
    $key_ab34 = { ff 5c [2] 8b 44 [2] cc 46 [2] 8b 57 [2] c5 5b [2] c9 51 [2] de 5a [2] c5 14 [2] f8 }

  condition:
    any of them
}