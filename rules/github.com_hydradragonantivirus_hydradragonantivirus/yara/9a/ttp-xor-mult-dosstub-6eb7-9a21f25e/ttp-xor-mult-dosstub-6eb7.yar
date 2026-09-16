rule TTP_XOR_MULT_DOSStub_6eb7 {
  strings:
    $key_6eb7 = { 3a df [2] 4e c7 [2] 09 c5 [2] 4e d4 [2] 00 d8 [2] 0c d2 [2] 1b d9 [2] 00 97 [2] 3d }

  condition:
    any of them
}