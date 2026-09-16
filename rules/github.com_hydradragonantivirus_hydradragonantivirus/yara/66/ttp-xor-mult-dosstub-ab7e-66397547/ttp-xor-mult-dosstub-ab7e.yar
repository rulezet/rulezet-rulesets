rule TTP_XOR_MULT_DOSStub_ab7e {
  strings:
    $key_ab7e = { ff 16 [2] 8b 0e [2] cc 0c [2] 8b 1d [2] c5 11 [2] c9 1b [2] de 10 [2] c5 5e [2] f8 }

  condition:
    any of them
}