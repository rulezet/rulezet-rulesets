rule TTP_XOR_MULT_DOSStub_5eba {
  strings:
    $key_5eba = { 0a d2 [2] 7e ca [2] 39 c8 [2] 7e d9 [2] 30 d5 [2] 3c df [2] 2b d4 [2] 30 9a [2] 0d }

  condition:
    any of them
}