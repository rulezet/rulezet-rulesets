rule TTP_XOR_MULT_DOSStub_ab35 {
  strings:
    $key_ab35 = { ff 5d [2] 8b 45 [2] cc 47 [2] 8b 56 [2] c5 5a [2] c9 50 [2] de 5b [2] c5 15 [2] f8 }

  condition:
    any of them
}