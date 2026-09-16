rule TTP_XOR_MULT_DOSStub_1bb7 {
  strings:
    $key_1bb7 = { 4f df [2] 3b c7 [2] 7c c5 [2] 3b d4 [2] 75 d8 [2] 79 d2 [2] 6e d9 [2] 75 97 [2] 48 }

  condition:
    any of them
}