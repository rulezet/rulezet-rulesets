rule TTP_XOR_MULT_DOSStub_abfa {
  strings:
    $key_abfa = { ff 92 [2] 8b 8a [2] cc 88 [2] 8b 99 [2] c5 95 [2] c9 9f [2] de 94 [2] c5 da [2] f8 }

  condition:
    any of them
}