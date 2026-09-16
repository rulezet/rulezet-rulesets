rule TTP_XOR_MULT_DOSStub_ab04 {
  strings:
    $key_ab04 = { ff 6c [2] 8b 74 [2] cc 76 [2] 8b 67 [2] c5 6b [2] c9 61 [2] de 6a [2] c5 24 [2] f8 }

  condition:
    any of them
}