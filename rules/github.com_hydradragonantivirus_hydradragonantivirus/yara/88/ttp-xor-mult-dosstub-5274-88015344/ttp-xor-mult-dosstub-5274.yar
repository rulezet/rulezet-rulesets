rule TTP_XOR_MULT_DOSStub_5274 {
  strings:
    $key_5274 = { 06 1c [2] 72 04 [2] 35 06 [2] 72 17 [2] 3c 1b [2] 30 11 [2] 27 1a [2] 3c 54 [2] 01 }

  condition:
    any of them
}