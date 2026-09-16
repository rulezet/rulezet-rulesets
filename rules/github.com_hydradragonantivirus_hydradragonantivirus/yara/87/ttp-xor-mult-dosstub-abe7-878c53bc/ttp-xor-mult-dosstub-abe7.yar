rule TTP_XOR_MULT_DOSStub_abe7 {
  strings:
    $key_abe7 = { ff 8f [2] 8b 97 [2] cc 95 [2] 8b 84 [2] c5 88 [2] c9 82 [2] de 89 [2] c5 c7 [2] f8 }

  condition:
    any of them
}