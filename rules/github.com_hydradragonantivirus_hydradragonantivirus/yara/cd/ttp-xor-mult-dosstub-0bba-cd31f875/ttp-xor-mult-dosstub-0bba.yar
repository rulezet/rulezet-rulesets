rule TTP_XOR_MULT_DOSStub_0bba {
  strings:
    $key_0bba = { 5f d2 [2] 2b ca [2] 6c c8 [2] 2b d9 [2] 65 d5 [2] 69 df [2] 7e d4 [2] 65 9a [2] 58 }

  condition:
    any of them
}