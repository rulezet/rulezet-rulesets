rule TTP_XOR_MULT_DOSStub_7855 {
  strings:
    $key_7855 = { 2c 3d [2] 58 25 [2] 1f 27 [2] 58 36 [2] 16 3a [2] 1a 30 [2] 0d 3b [2] 16 75 [2] 2b }

  condition:
    any of them
}