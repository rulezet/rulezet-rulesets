rule TTP_XOR_MULT_DOSStub_0bb7 {
  strings:
    $key_0bb7 = { 5f df [2] 2b c7 [2] 6c c5 [2] 2b d4 [2] 65 d8 [2] 69 d2 [2] 7e d9 [2] 65 97 [2] 58 }

  condition:
    any of them
}