rule TTP_XOR_MULT_DOSStub_6446 {
  strings:
    $key_6446 = { 30 2e [2] 44 36 [2] 03 34 [2] 44 25 [2] 0a 29 [2] 06 23 [2] 11 28 [2] 0a 66 [2] 37 }

  condition:
    any of them
}