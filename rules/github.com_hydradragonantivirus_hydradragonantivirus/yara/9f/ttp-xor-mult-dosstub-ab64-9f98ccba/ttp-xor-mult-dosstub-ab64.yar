rule TTP_XOR_MULT_DOSStub_ab64 {
  strings:
    $key_ab64 = { ff 0c [2] 8b 14 [2] cc 16 [2] 8b 07 [2] c5 0b [2] c9 01 [2] de 0a [2] c5 44 [2] f8 }

  condition:
    any of them
}