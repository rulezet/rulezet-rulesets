rule TTP_XOR_MULT_DOSStub_ab5b {
  strings:
    $key_ab5b = { ff 33 [2] 8b 2b [2] cc 29 [2] 8b 38 [2] c5 34 [2] c9 3e [2] de 35 [2] c5 7b [2] f8 }

  condition:
    any of them
}