rule TTP_XOR_MULT_DOSStub_5379 {
  strings:
    $key_5379 = { 07 11 [2] 73 09 [2] 34 0b [2] 73 1a [2] 3d 16 [2] 31 1c [2] 26 17 [2] 3d 59 [2] 00 }

  condition:
    any of them
}