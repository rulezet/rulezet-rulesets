rule TTP_XOR_MULT_DOSStub_5404 {
  strings:
    $key_5404 = { 00 6c [2] 74 74 [2] 33 76 [2] 74 67 [2] 3a 6b [2] 36 61 [2] 21 6a [2] 3a 24 [2] 07 }

  condition:
    any of them
}