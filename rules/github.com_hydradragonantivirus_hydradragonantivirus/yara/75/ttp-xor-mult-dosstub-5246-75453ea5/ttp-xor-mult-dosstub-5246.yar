rule TTP_XOR_MULT_DOSStub_5246 {
  strings:
    $key_5246 = { 06 2e [2] 72 36 [2] 35 34 [2] 72 25 [2] 3c 29 [2] 30 23 [2] 27 28 [2] 3c 66 [2] 01 }

  condition:
    any of them
}