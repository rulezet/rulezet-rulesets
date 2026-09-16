rule TTP_XOR_MULT_DOSStub_abfb {
  strings:
    $key_abfb = { ff 93 [2] 8b 8b [2] cc 89 [2] 8b 98 [2] c5 94 [2] c9 9e [2] de 95 [2] c5 db [2] f8 }

  condition:
    any of them
}