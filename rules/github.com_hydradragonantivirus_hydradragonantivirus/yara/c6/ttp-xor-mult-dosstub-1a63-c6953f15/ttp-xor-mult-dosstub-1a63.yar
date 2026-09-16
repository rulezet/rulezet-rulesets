rule TTP_XOR_MULT_DOSStub_1a63 {
  strings:
    $key_1a63 = { 4e 0b [2] 3a 13 [2] 7d 11 [2] 3a 00 [2] 74 0c [2] 78 06 [2] 6f 0d [2] 74 43 [2] 49 }

  condition:
    any of them
}