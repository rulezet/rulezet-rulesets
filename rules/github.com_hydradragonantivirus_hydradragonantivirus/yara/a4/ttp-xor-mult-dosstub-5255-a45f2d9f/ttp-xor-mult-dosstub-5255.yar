rule TTP_XOR_MULT_DOSStub_5255 {
  strings:
    $key_5255 = { 06 3d [2] 72 25 [2] 35 27 [2] 72 36 [2] 3c 3a [2] 30 30 [2] 27 3b [2] 3c 75 [2] 01 }

  condition:
    any of them
}