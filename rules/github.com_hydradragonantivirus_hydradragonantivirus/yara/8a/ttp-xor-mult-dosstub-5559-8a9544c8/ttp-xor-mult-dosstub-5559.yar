rule TTP_XOR_MULT_DOSStub_5559 {
  strings:
    $key_5559 = { 01 31 [2] 75 29 [2] 32 2b [2] 75 3a [2] 3b 36 [2] 37 3c [2] 20 37 [2] 3b 79 [2] 06 }

  condition:
    any of them
}