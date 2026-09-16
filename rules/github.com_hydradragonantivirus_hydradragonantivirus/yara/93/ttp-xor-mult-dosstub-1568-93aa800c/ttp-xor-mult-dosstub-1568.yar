rule TTP_XOR_MULT_DOSStub_1568 {
  strings:
    $key_1568 = { 41 00 [2] 35 18 [2] 72 1a [2] 35 0b [2] 7b 07 [2] 77 0d [2] 60 06 [2] 7b 48 [2] 46 }

  condition:
    any of them
}