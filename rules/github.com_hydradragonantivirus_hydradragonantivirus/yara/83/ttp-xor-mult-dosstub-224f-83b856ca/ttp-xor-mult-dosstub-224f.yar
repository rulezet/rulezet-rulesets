rule TTP_XOR_MULT_DOSStub_224f {
  strings:
    $key_224f = { 76 27 [2] 02 3f [2] 45 3d [2] 02 2c [2] 4c 20 [2] 40 2a [2] 57 21 [2] 4c 6f [2] 71 }

  condition:
    any of them
}