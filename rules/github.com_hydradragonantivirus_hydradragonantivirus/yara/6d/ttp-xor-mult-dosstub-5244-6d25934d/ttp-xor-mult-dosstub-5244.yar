rule TTP_XOR_MULT_DOSStub_5244 {
  strings:
    $key_5244 = { 06 2c [2] 72 34 [2] 35 36 [2] 72 27 [2] 3c 2b [2] 30 21 [2] 27 2a [2] 3c 64 [2] 01 }

  condition:
    any of them
}