rule TTP_XOR_MULT_DOSStub_5576 {
  strings:
    $key_5576 = { 01 1e [2] 75 06 [2] 32 04 [2] 75 15 [2] 3b 19 [2] 37 13 [2] 20 18 [2] 3b 56 [2] 06 }

  condition:
    any of them
}