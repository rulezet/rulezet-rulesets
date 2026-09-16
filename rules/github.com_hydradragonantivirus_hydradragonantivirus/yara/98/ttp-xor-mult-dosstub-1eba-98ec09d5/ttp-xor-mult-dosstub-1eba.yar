rule TTP_XOR_MULT_DOSStub_1eba {
  strings:
    $key_1eba = { 4a d2 [2] 3e ca [2] 79 c8 [2] 3e d9 [2] 70 d5 [2] 7c df [2] 6b d4 [2] 70 9a [2] 4d }

  condition:
    any of them
}