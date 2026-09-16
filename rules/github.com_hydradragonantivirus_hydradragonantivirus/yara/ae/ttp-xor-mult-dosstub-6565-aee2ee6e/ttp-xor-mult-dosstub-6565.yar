rule TTP_XOR_MULT_DOSStub_6565 {
  strings:
    $key_6565 = { 31 0d [2] 45 15 [2] 02 17 [2] 45 06 [2] 0b 0a [2] 07 00 [2] 10 0b [2] 0b 45 [2] 36 }

  condition:
    any of them
}