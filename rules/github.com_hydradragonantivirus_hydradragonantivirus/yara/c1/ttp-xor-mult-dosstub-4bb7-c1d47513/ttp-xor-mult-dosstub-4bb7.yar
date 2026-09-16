rule TTP_XOR_MULT_DOSStub_4bb7 {
  strings:
    $key_4bb7 = { 1f df [2] 6b c7 [2] 2c c5 [2] 6b d4 [2] 25 d8 [2] 29 d2 [2] 3e d9 [2] 25 97 [2] 18 }

  condition:
    any of them
}