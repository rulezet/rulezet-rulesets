rule TTP_XOR_MULT_DOSStub_7a63 {
  strings:
    $key_7a63 = { 2e 0b [2] 5a 13 [2] 1d 11 [2] 5a 00 [2] 14 0c [2] 18 06 [2] 0f 0d [2] 14 43 [2] 29 }

  condition:
    any of them
}