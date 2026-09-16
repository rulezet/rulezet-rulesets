rule TTP_XOR_MULT_DOSStub_ab51 {
  strings:
    $key_ab51 = { ff 39 [2] 8b 21 [2] cc 23 [2] 8b 32 [2] c5 3e [2] c9 34 [2] de 3f [2] c5 71 [2] f8 }

  condition:
    any of them
}