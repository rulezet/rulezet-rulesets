rule TTP_XOR_MULT_DOSStub_6ea8 {
  strings:
    $key_6ea8 = { 3a c0 [2] 4e d8 [2] 09 da [2] 4e cb [2] 00 c7 [2] 0c cd [2] 1b c6 [2] 00 88 [2] 3d }

  condition:
    any of them
}