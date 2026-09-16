rule TTP_XOR_MULT_DOSStub_4365 {
  strings:
    $key_4365 = { 17 0d [2] 63 15 [2] 24 17 [2] 63 06 [2] 2d 0a [2] 21 00 [2] 36 0b [2] 2d 45 [2] 10 }

  condition:
    any of them
}