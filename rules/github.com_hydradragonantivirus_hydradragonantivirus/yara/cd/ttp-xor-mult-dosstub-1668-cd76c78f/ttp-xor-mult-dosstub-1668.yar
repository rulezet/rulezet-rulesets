rule TTP_XOR_MULT_DOSStub_1668 {
  strings:
    $key_1668 = { 42 00 [2] 36 18 [2] 71 1a [2] 36 0b [2] 78 07 [2] 74 0d [2] 63 06 [2] 78 48 [2] 45 }

  condition:
    any of them
}