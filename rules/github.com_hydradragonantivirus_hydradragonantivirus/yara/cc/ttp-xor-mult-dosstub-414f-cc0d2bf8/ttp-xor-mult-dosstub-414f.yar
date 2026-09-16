rule TTP_XOR_MULT_DOSStub_414f {
  strings:
    $key_414f = { 15 27 [2] 61 3f [2] 26 3d [2] 61 2c [2] 2f 20 [2] 23 2a [2] 34 21 [2] 2f 6f [2] 12 }

  condition:
    any of them
}