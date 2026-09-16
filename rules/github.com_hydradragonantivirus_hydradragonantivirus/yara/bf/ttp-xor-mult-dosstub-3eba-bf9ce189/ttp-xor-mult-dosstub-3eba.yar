rule TTP_XOR_MULT_DOSStub_3eba {
  strings:
    $key_3eba = { 6a d2 [2] 1e ca [2] 59 c8 [2] 1e d9 [2] 50 d5 [2] 5c df [2] 4b d4 [2] 50 9a [2] 6d }

  condition:
    any of them
}