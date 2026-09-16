rule TTP_XOR_MULT_DOSStub_7446 {
  strings:
    $key_7446 = { 20 2e [2] 54 36 [2] 13 34 [2] 54 25 [2] 1a 29 [2] 16 23 [2] 01 28 [2] 1a 66 [2] 27 }

  condition:
    any of them
}