rule TTP_XOR_MULT_DOSStub_1763 {
  strings:
    $key_1763 = { 43 0b [2] 37 13 [2] 70 11 [2] 37 00 [2] 79 0c [2] 75 06 [2] 62 0d [2] 79 43 [2] 44 }

  condition:
    any of them
}