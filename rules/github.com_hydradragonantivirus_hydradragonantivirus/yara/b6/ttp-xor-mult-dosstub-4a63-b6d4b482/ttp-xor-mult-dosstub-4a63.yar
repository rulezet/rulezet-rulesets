rule TTP_XOR_MULT_DOSStub_4a63 {
  strings:
    $key_4a63 = { 1e 0b [2] 6a 13 [2] 2d 11 [2] 6a 00 [2] 24 0c [2] 28 06 [2] 3f 0d [2] 24 43 [2] 19 }

  condition:
    any of them
}