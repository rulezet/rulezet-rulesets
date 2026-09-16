rule TTP_XOR_MULT_DOSStub_ab6e {
  strings:
    $key_ab6e = { ff 06 [2] 8b 1e [2] cc 1c [2] 8b 0d [2] c5 01 [2] c9 0b [2] de 00 [2] c5 4e [2] f8 }

  condition:
    any of them
}