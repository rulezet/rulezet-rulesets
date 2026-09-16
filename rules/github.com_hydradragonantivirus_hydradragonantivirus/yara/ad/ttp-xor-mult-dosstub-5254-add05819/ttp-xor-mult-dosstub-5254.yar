rule TTP_XOR_MULT_DOSStub_5254 {
  strings:
    $key_5254 = { 06 3c [2] 72 24 [2] 35 26 [2] 72 37 [2] 3c 3b [2] 30 31 [2] 27 3a [2] 3c 74 [2] 01 }

  condition:
    any of them
}