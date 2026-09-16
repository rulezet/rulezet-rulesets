rule TTP_XOR_MULT_DOSStub_0565 {
  strings:
    $key_0565 = { 51 0d [2] 25 15 [2] 62 17 [2] 25 06 [2] 6b 0a [2] 67 00 [2] 70 0b [2] 6b 45 [2] 56 }

  condition:
    any of them
}