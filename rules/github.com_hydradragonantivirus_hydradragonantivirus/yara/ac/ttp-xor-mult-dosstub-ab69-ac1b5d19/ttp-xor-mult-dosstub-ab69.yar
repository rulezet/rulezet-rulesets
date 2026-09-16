rule TTP_XOR_MULT_DOSStub_ab69 {
  strings:
    $key_ab69 = { ff 01 [2] 8b 19 [2] cc 1b [2] 8b 0a [2] c5 06 [2] c9 0c [2] de 07 [2] c5 49 [2] f8 }

  condition:
    any of them
}