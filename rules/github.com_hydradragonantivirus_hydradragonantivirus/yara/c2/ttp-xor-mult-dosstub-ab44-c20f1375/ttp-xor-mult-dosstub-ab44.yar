rule TTP_XOR_MULT_DOSStub_ab44 {
  strings:
    $key_ab44 = { ff 2c [2] 8b 34 [2] cc 36 [2] 8b 27 [2] c5 2b [2] c9 21 [2] de 2a [2] c5 64 [2] f8 }

  condition:
    any of them
}