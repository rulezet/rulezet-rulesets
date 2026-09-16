rule TTP_XOR_MULT_DOSStub_69a4 {
  strings:
    $key_69a4 = { 3d cc [2] 49 d4 [2] 0e d6 [2] 49 c7 [2] 07 cb [2] 0b c1 [2] 1c ca [2] 07 84 [2] 3a }

  condition:
    any of them
}