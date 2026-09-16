rule TTP_XOR_MULT_DOSStub_5364 {
  strings:
    $key_5364 = { 07 0c [2] 73 14 [2] 34 16 [2] 73 07 [2] 3d 0b [2] 31 01 [2] 26 0a [2] 3d 44 [2] 00 }

  condition:
    any of them
}