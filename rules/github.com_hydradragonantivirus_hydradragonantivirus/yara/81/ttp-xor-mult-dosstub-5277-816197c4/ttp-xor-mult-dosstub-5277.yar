rule TTP_XOR_MULT_DOSStub_5277 {
  strings:
    $key_5277 = { 06 1f [2] 72 07 [2] 35 05 [2] 72 14 [2] 3c 18 [2] 30 12 [2] 27 19 [2] 3c 57 [2] 01 }

  condition:
    any of them
}