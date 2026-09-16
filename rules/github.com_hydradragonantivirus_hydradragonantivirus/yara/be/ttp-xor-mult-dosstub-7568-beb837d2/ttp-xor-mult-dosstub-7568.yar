rule TTP_XOR_MULT_DOSStub_7568 {
  strings:
    $key_7568 = { 21 00 [2] 55 18 [2] 12 1a [2] 55 0b [2] 1b 07 [2] 17 0d [2] 00 06 [2] 1b 48 [2] 26 }

  condition:
    any of them
}