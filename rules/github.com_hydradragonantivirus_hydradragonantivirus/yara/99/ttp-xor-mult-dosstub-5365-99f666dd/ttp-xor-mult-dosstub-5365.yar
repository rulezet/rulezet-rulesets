rule TTP_XOR_MULT_DOSStub_5365 {
  strings:
    $key_5365 = { 07 0d [2] 73 15 [2] 34 17 [2] 73 06 [2] 3d 0a [2] 31 00 [2] 26 0b [2] 3d 45 [2] 00 }

  condition:
    any of them
}