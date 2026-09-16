rule TTP_XOR_MULT_DOSStub_ab67 {
  strings:
    $key_ab67 = { ff 0f [2] 8b 17 [2] cc 15 [2] 8b 04 [2] c5 08 [2] c9 02 [2] de 09 [2] c5 47 [2] f8 }

  condition:
    any of them
}