rule TTP_XOR_MULT_DOSStub_3bba {
  strings:
    $key_3bba = { 6f d2 [2] 1b ca [2] 5c c8 [2] 1b d9 [2] 55 d5 [2] 59 df [2] 4e d4 [2] 55 9a [2] 68 }

  condition:
    any of them
}