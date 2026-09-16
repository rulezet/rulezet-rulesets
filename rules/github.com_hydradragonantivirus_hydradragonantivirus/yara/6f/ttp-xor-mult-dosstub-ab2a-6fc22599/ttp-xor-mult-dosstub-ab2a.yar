rule TTP_XOR_MULT_DOSStub_ab2a {
  strings:
    $key_ab2a = { ff 42 [2] 8b 5a [2] cc 58 [2] 8b 49 [2] c5 45 [2] c9 4f [2] de 44 [2] c5 0a [2] f8 }

  condition:
    any of them
}