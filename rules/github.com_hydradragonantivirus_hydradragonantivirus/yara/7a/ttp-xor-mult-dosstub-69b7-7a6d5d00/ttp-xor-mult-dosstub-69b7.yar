rule TTP_XOR_MULT_DOSStub_69b7 {
  strings:
    $key_69b7 = { 3d df [2] 49 c7 [2] 0e c5 [2] 49 d4 [2] 07 d8 [2] 0b d2 [2] 1c d9 [2] 07 97 [2] 3a }

  condition:
    any of them
}