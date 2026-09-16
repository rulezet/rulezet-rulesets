rule TTP_XOR_MULT_DOSStub_7504 {
  strings:
    $key_7504 = { 21 6c [2] 55 74 [2] 12 76 [2] 55 67 [2] 1b 6b [2] 17 61 [2] 00 6a [2] 1b 24 [2] 26 }

  condition:
    any of them
}