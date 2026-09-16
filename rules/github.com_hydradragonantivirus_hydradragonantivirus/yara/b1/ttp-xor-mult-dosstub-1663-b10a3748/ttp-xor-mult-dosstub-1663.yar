rule TTP_XOR_MULT_DOSStub_1663 {
  strings:
    $key_1663 = { 42 0b [2] 36 13 [2] 71 11 [2] 36 00 [2] 78 0c [2] 74 06 [2] 63 0d [2] 78 43 [2] 45 }

  condition:
    any of them
}