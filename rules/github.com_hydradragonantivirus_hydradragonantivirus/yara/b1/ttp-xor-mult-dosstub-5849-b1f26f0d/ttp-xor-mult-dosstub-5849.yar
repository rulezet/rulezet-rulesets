rule TTP_XOR_MULT_DOSStub_5849 {
  strings:
    $key_5849 = { 0c 21 [2] 78 39 [2] 3f 3b [2] 78 2a [2] 36 26 [2] 3a 2c [2] 2d 27 [2] 36 69 [2] 0b }

  condition:
    any of them
}