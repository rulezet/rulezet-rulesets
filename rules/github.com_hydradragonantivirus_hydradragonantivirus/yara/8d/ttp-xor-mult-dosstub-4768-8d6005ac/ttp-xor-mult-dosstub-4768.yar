rule TTP_XOR_MULT_DOSStub_4768 {
  strings:
    $key_4768 = { 13 00 [2] 67 18 [2] 20 1a [2] 67 0b [2] 29 07 [2] 25 0d [2] 32 06 [2] 29 48 [2] 14 }

  condition:
    any of them
}