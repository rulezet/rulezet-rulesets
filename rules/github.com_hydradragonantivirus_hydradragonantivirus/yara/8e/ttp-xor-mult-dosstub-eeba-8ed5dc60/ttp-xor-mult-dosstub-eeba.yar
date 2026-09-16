rule TTP_XOR_MULT_DOSStub_eeba {
  strings:
    $key_eeba = { ba d2 [2] ce ca [2] 89 c8 [2] ce d9 [2] 80 d5 [2] 8c df [2] 9b d4 [2] 80 9a [2] bd }

  condition:
    any of them
}