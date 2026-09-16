rule TTP_XOR_MULT_DOSStub_6eba {
  strings:
    $key_6eba = { 3a d2 [2] 4e ca [2] 09 c8 [2] 4e d9 [2] 00 d5 [2] 0c df [2] 1b d4 [2] 00 9a [2] 3d }

  condition:
    any of them
}