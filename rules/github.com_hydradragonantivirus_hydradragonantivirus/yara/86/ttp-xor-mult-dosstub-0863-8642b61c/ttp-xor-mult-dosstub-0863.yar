rule TTP_XOR_MULT_DOSStub_0863 {
  strings:
    $key_0863 = { 5c 0b [2] 28 13 [2] 6f 11 [2] 28 00 [2] 66 0c [2] 6a 06 [2] 7d 0d [2] 66 43 [2] 5b }

  condition:
    any of them
}