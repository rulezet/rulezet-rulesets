rule TTP_XOR_MULT_DOSStub_abf5 {
  strings:
    $key_abf5 = { ff 9d [2] 8b 85 [2] cc 87 [2] 8b 96 [2] c5 9a [2] c9 90 [2] de 9b [2] c5 d5 [2] f8 }

  condition:
    any of them
}