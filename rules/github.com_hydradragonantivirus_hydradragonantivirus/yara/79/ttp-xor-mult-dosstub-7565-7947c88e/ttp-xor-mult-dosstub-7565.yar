rule TTP_XOR_MULT_DOSStub_7565 {
  strings:
    $key_7565 = { 21 0d [2] 55 15 [2] 12 17 [2] 55 06 [2] 1b 0a [2] 17 00 [2] 00 0b [2] 1b 45 [2] 26 }

  condition:
    any of them
}