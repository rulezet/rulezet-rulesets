rule TTP_XOR_MULT_DOSStub_5463 {
  strings:
    $key_5463 = { 00 0b [2] 74 13 [2] 33 11 [2] 74 00 [2] 3a 0c [2] 36 06 [2] 21 0d [2] 3a 43 [2] 07 }

  condition:
    any of them
}