rule TTP_XOR_MULT_DOSStub_5279 {
  strings:
    $key_5279 = { 06 11 [2] 72 09 [2] 35 0b [2] 72 1a [2] 3c 16 [2] 30 1c [2] 27 17 [2] 3c 59 [2] 01 }

  condition:
    any of them
}