rule TTP_XOR_MULT_DOSStub_7765 {
  strings:
    $key_7765 = { 23 0d [2] 57 15 [2] 10 17 [2] 57 06 [2] 19 0a [2] 15 00 [2] 02 0b [2] 19 45 [2] 24 }

  condition:
    any of them
}