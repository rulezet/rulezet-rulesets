rule TTP_XOR_MULT_DOSStub_5275 {
  strings:
    $key_5275 = { 06 1d [2] 72 05 [2] 35 07 [2] 72 16 [2] 3c 1a [2] 30 10 [2] 27 1b [2] 3c 55 [2] 01 }

  condition:
    any of them
}