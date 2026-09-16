rule TTP_XOR_MULT_DOSStub_5665 {
  strings:
    $key_5665 = { 02 0d [2] 76 15 [2] 31 17 [2] 76 06 [2] 38 0a [2] 34 00 [2] 23 0b [2] 38 45 [2] 05 }

  condition:
    any of them
}