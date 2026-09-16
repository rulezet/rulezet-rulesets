rule TTP_XOR_MULT_DOSStub_4559 {
  strings:
    $key_4559 = { 11 31 [2] 65 29 [2] 22 2b [2] 65 3a [2] 2b 36 [2] 27 3c [2] 30 37 [2] 2b 79 [2] 16 }

  condition:
    any of them
}