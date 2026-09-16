rule TTP_XOR_MULT_DOSStub_7eb7 {
  strings:
    $key_7eb7 = { 2a df [2] 5e c7 [2] 19 c5 [2] 5e d4 [2] 10 d8 [2] 1c d2 [2] 0b d9 [2] 10 97 [2] 2d }

  condition:
    any of them
}