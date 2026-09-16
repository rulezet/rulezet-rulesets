rule TTP_XOR_MULT_DOSStub_7858 {
  strings:
    $key_7858 = { 2c 30 [2] 58 28 [2] 1f 2a [2] 58 3b [2] 16 37 [2] 1a 3d [2] 0d 36 [2] 16 78 [2] 2b }

  condition:
    any of them
}