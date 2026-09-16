rule TTP_XOR_MULT_DOSStub_0765 {
  strings:
    $key_0765 = { 53 0d [2] 27 15 [2] 60 17 [2] 27 06 [2] 69 0a [2] 65 00 [2] 72 0b [2] 69 45 [2] 54 }

  condition:
    any of them
}