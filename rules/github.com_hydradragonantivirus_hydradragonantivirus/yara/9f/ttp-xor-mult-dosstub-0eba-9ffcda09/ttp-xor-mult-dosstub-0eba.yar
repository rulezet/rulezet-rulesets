rule TTP_XOR_MULT_DOSStub_0eba {
  strings:
    $key_0eba = { 5a d2 [2] 2e ca [2] 69 c8 [2] 2e d9 [2] 60 d5 [2] 6c df [2] 7b d4 [2] 60 9a [2] 5d }

  condition:
    any of them
}