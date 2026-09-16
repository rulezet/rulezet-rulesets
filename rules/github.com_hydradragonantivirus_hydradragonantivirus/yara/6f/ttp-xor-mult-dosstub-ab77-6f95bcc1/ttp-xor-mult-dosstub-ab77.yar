rule TTP_XOR_MULT_DOSStub_ab77 {
  strings:
    $key_ab77 = { ff 1f [2] 8b 07 [2] cc 05 [2] 8b 14 [2] c5 18 [2] c9 12 [2] de 19 [2] c5 57 [2] f8 }

  condition:
    any of them
}