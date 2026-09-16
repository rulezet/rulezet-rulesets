rule TTP_XOR_MULT_DOSStub_5565 {
  strings:
    $key_5565 = { 01 0d [2] 75 15 [2] 32 17 [2] 75 06 [2] 3b 0a [2] 37 00 [2] 20 0b [2] 3b 45 [2] 06 }

  condition:
    any of them
}