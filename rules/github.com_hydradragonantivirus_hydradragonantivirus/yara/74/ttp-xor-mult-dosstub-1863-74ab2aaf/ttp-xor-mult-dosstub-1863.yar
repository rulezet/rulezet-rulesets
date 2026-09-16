rule TTP_XOR_MULT_DOSStub_1863 {
  strings:
    $key_1863 = { 4c 0b [2] 38 13 [2] 7f 11 [2] 38 00 [2] 76 0c [2] 7a 06 [2] 6d 0d [2] 76 43 [2] 4b }

  condition:
    any of them
}