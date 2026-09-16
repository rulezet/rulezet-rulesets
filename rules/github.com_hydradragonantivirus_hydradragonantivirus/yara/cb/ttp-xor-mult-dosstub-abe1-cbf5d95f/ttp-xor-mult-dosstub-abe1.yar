rule TTP_XOR_MULT_DOSStub_abe1 {
  strings:
    $key_abe1 = { ff 89 [2] 8b 91 [2] cc 93 [2] 8b 82 [2] c5 8e [2] c9 84 [2] de 8f [2] c5 c1 [2] f8 }

  condition:
    any of them
}