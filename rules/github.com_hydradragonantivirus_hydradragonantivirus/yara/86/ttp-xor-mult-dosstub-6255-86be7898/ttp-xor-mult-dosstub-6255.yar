rule TTP_XOR_MULT_DOSStub_6255 {
  strings:
    $key_6255 = { 36 3d [2] 42 25 [2] 05 27 [2] 42 36 [2] 0c 3a [2] 00 30 [2] 17 3b [2] 0c 75 [2] 31 }

  condition:
    any of them
}