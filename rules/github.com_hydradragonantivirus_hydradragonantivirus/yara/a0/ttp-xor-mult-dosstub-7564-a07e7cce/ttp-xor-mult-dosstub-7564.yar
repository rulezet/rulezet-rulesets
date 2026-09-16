rule TTP_XOR_MULT_DOSStub_7564 {
  strings:
    $key_7564 = { 21 0c [2] 55 14 [2] 12 16 [2] 55 07 [2] 1b 0b [2] 17 01 [2] 00 0a [2] 1b 44 [2] 26 }

  condition:
    any of them
}