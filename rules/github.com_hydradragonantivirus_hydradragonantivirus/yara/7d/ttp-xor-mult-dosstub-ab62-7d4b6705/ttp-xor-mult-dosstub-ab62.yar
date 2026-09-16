rule TTP_XOR_MULT_DOSStub_ab62 {
  strings:
    $key_ab62 = { ff 0a [2] 8b 12 [2] cc 10 [2] 8b 01 [2] c5 0d [2] c9 07 [2] de 0c [2] c5 42 [2] f8 }

  condition:
    any of them
}