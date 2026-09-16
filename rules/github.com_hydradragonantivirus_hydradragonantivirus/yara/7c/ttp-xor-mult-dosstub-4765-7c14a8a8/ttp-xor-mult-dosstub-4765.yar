rule TTP_XOR_MULT_DOSStub_4765 {
  strings:
    $key_4765 = { 13 0d [2] 67 15 [2] 20 17 [2] 67 06 [2] 29 0a [2] 25 00 [2] 32 0b [2] 29 45 [2] 14 }

  condition:
    any of them
}