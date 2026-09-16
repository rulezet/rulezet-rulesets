rule TTP_XOR_MULT_DOSStub_c8b7 {
  strings:
    $key_c8b7 = { 9c df [2] e8 c7 [2] af c5 [2] e8 d4 [2] a6 d8 [2] aa d2 [2] bd d9 [2] a6 97 [2] 9b }

  condition:
    any of them
}