rule TTP_XOR_MULT_DOSStub_0065 {
  strings:
    $key_0065 = { 54 0d [2] 20 15 [2] 67 17 [2] 20 06 [2] 6e 0a [2] 62 00 [2] 75 0b [2] 6e 45 [2] 53 }

  condition:
    any of them
}