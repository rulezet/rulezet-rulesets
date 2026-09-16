rule TTP_XOR_MULT_DOSStub_7063 {
  strings:
    $key_7063 = { 24 0b [2] 50 13 [2] 17 11 [2] 50 00 [2] 1e 0c [2] 12 06 [2] 05 0d [2] 1e 43 [2] 23 }

  condition:
    any of them
}