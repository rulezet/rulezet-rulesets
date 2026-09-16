rule TTP_XOR_MULT_DOSStub_784f {
  strings:
    $key_784f = { 2c 27 [2] 58 3f [2] 1f 3d [2] 58 2c [2] 16 20 [2] 1a 2a [2] 0d 21 [2] 16 6f [2] 2b }

  condition:
    any of them
}