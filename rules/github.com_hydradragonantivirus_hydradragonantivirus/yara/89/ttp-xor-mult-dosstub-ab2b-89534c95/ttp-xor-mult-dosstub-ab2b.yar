rule TTP_XOR_MULT_DOSStub_ab2b {
  strings:
    $key_ab2b = { ff 43 [2] 8b 5b [2] cc 59 [2] 8b 48 [2] c5 44 [2] c9 4e [2] de 45 [2] c5 0b [2] f8 }

  condition:
    any of them
}