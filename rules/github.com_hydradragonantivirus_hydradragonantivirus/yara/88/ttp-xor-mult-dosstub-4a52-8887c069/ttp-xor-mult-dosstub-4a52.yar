rule TTP_XOR_MULT_DOSStub_4a52 {
  strings:
    $key_4a52 = { 1e 3a [2] 6a 22 [2] 2d 20 [2] 6a 31 [2] 24 3d [2] 28 37 [2] 3f 3c [2] 24 72 [2] 19 }

  condition:
    any of them
}