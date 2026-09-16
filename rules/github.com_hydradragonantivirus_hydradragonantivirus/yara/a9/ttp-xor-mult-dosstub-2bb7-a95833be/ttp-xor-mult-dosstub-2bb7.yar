rule TTP_XOR_MULT_DOSStub_2bb7 {
  strings:
    $key_2bb7 = { 7f df [2] 0b c7 [2] 4c c5 [2] 0b d4 [2] 45 d8 [2] 49 d2 [2] 5e d9 [2] 45 97 [2] 78 }

  condition:
    any of them
}