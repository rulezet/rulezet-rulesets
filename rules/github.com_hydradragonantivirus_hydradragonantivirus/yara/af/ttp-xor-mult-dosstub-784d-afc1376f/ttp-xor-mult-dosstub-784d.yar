rule TTP_XOR_MULT_DOSStub_784d {
  strings:
    $key_784d = { 2c 25 [2] 58 3d [2] 1f 3f [2] 58 2e [2] 16 22 [2] 1a 28 [2] 0d 23 [2] 16 6d [2] 2b }

  condition:
    any of them
}