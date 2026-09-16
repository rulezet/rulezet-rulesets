rule TTP_XOR_MULT_DOSStub_ab21 {
  strings:
    $key_ab21 = { ff 49 [2] 8b 51 [2] cc 53 [2] 8b 42 [2] c5 4e [2] c9 44 [2] de 4f [2] c5 01 [2] f8 }

  condition:
    any of them
}