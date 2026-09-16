rule TTP_XOR_MULT_DOSStub_1ea8 {
  strings:
    $key_1ea8 = { 4a c0 [2] 3e d8 [2] 79 da [2] 3e cb [2] 70 c7 [2] 7c cd [2] 6b c6 [2] 70 88 [2] 4d }

  condition:
    any of them
}