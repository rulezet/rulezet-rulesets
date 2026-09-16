rule TTP_XOR_MULT_DOSStub_abf0 {
  strings:
    $key_abf0 = { ff 98 [2] 8b 80 [2] cc 82 [2] 8b 93 [2] c5 9f [2] c9 95 [2] de 9e [2] c5 d0 [2] f8 }

  condition:
    any of them
}