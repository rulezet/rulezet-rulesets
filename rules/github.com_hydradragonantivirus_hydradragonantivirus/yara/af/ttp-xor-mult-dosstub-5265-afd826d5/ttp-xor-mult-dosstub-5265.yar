rule TTP_XOR_MULT_DOSStub_5265 {
  strings:
    $key_5265 = { 06 0d [2] 72 15 [2] 35 17 [2] 72 06 [2] 3c 0a [2] 30 00 [2] 27 0b [2] 3c 45 [2] 01 }

  condition:
    any of them
}