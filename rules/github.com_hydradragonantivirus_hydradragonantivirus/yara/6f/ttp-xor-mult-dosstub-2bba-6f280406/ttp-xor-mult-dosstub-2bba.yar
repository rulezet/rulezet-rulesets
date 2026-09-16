rule TTP_XOR_MULT_DOSStub_2bba {
  strings:
    $key_2bba = { 7f d2 [2] 0b ca [2] 4c c8 [2] 0b d9 [2] 45 d5 [2] 49 df [2] 5e d4 [2] 45 9a [2] 78 }

  condition:
    any of them
}