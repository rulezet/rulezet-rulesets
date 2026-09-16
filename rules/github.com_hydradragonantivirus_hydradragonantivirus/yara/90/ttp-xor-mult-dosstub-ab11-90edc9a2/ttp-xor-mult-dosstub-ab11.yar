rule TTP_XOR_MULT_DOSStub_ab11 {
  strings:
    $key_ab11 = { ff 79 [2] 8b 61 [2] cc 63 [2] 8b 72 [2] c5 7e [2] c9 74 [2] de 7f [2] c5 31 [2] f8 }

  condition:
    any of them
}