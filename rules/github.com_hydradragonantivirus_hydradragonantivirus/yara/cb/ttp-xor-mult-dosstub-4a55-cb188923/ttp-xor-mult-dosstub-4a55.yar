rule TTP_XOR_MULT_DOSStub_4a55 {
  strings:
    $key_4a55 = { 1e 3d [2] 6a 25 [2] 2d 27 [2] 6a 36 [2] 24 3a [2] 28 30 [2] 3f 3b [2] 24 75 [2] 19 }

  condition:
    any of them
}