rule TTP_XOR_MULT_DOSStub_ab59 {
  strings:
    $key_ab59 = { ff 31 [2] 8b 29 [2] cc 2b [2] 8b 3a [2] c5 36 [2] c9 3c [2] de 37 [2] c5 79 [2] f8 }

  condition:
    any of them
}