rule TTP_XOR_MULT_DOSStub_feba {
  strings:
    $key_feba = { aa d2 [2] de ca [2] 99 c8 [2] de d9 [2] 90 d5 [2] 9c df [2] 8b d4 [2] 90 9a [2] ad }

  condition:
    any of them
}