rule TTP_XOR_MULT_DOSStub_4668 {
  strings:
    $key_4668 = { 12 00 [2] 66 18 [2] 21 1a [2] 66 0b [2] 28 07 [2] 24 0d [2] 33 06 [2] 28 48 [2] 15 }

  condition:
    any of them
}