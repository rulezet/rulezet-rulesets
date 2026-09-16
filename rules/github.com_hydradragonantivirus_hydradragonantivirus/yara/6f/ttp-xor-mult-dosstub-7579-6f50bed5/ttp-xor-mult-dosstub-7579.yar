rule TTP_XOR_MULT_DOSStub_7579 {
  strings:
    $key_7579 = { 21 11 [2] 55 09 [2] 12 0b [2] 55 1a [2] 1b 16 [2] 17 1c [2] 00 17 [2] 1b 59 [2] 26 }

  condition:
    any of them
}