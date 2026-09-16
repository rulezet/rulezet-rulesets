rule TTP_XOR_MULT_DOSStub_7bb7 {
  strings:
    $key_7bb7 = { 2f df [2] 5b c7 [2] 1c c5 [2] 5b d4 [2] 15 d8 [2] 19 d2 [2] 0e d9 [2] 15 97 [2] 28 }

  condition:
    any of them
}