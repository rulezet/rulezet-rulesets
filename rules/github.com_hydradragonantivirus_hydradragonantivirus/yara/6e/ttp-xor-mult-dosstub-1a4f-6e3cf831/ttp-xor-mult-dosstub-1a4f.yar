rule TTP_XOR_MULT_DOSStub_1a4f {
  strings:
    $key_1a4f = { 4e 27 [2] 3a 3f [2] 7d 3d [2] 3a 2c [2] 74 20 [2] 78 2a [2] 6f 21 [2] 74 6f [2] 49 }

  condition:
    any of them
}