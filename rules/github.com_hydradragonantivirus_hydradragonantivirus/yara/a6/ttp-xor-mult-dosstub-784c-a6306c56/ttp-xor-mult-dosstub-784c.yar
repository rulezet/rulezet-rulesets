rule TTP_XOR_MULT_DOSStub_784c {
  strings:
    $key_784c = { 2c 24 [2] 58 3c [2] 1f 3e [2] 58 2f [2] 16 23 [2] 1a 29 [2] 0d 22 [2] 16 6c [2] 2b }

  condition:
    any of them
}