rule TTP_XOR_MULT_DOSStub_5348 {
  strings:
    $key_5348 = { 07 20 [2] 73 38 [2] 34 3a [2] 73 2b [2] 3d 27 [2] 31 2d [2] 26 26 [2] 3d 68 [2] 00 }

  condition:
    any of them
}