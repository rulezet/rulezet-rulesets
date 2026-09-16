rule TTP_XOR_MULT_DOSStub_1774 {
  strings:
    $key_1774 = { 43 1c [2] 37 04 [2] 70 06 [2] 37 17 [2] 79 1b [2] 75 11 [2] 62 1a [2] 79 54 [2] 44 }

  condition:
    any of them
}