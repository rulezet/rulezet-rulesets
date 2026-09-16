rule TTP_XOR_MULT_DOSStub_ab08 {
  strings:
    $key_ab08 = { ff 60 [2] 8b 78 [2] cc 7a [2] 8b 6b [2] c5 67 [2] c9 6d [2] de 66 [2] c5 28 [2] f8 }

  condition:
    any of them
}