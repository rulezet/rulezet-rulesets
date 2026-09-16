rule TTP_XOR_MULT_DOSStub_5834 {
  strings:
    $key_5834 = { 0c 5c [2] 78 44 [2] 3f 46 [2] 78 57 [2] 36 5b [2] 3a 51 [2] 2d 5a [2] 36 14 [2] 0b }

  condition:
    any of them
}