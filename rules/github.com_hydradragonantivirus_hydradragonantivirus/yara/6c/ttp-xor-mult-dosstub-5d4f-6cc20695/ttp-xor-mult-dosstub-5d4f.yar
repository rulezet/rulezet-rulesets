rule TTP_XOR_MULT_DOSStub_5d4f {
  strings:
    $key_5d4f = { 09 27 [2] 7d 3f [2] 3a 3d [2] 7d 2c [2] 33 20 [2] 3f 2a [2] 28 21 [2] 33 6f [2] 0e }

  condition:
    any of them
}