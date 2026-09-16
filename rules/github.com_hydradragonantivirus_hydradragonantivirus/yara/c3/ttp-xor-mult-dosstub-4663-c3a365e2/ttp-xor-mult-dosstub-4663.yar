rule TTP_XOR_MULT_DOSStub_4663 {
  strings:
    $key_4663 = { 12 0b [2] 66 13 [2] 21 11 [2] 66 00 [2] 28 0c [2] 24 06 [2] 33 0d [2] 28 43 [2] 15 }

  condition:
    any of them
}