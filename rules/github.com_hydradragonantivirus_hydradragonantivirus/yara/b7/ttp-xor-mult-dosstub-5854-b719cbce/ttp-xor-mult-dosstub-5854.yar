rule TTP_XOR_MULT_DOSStub_5854 {
  strings:
    $key_5854 = { 0c 3c [2] 78 24 [2] 3f 26 [2] 78 37 [2] 36 3b [2] 3a 31 [2] 2d 3a [2] 36 74 [2] 0b }

  condition:
    any of them
}