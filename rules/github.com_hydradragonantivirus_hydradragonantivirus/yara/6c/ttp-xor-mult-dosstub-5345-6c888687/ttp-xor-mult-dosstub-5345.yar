rule TTP_XOR_MULT_DOSStub_5345 {
  strings:
    $key_5345 = { 07 2d [2] 73 35 [2] 34 37 [2] 73 26 [2] 3d 2a [2] 31 20 [2] 26 2b [2] 3d 65 [2] 00 }

  condition:
    any of them
}