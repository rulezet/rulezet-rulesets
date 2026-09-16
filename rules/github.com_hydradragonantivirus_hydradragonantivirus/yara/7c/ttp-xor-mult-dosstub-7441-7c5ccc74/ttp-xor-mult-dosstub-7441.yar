rule TTP_XOR_MULT_DOSStub_7441 {
  strings:
    $key_7441 = { 20 29 [2] 54 31 [2] 13 33 [2] 54 22 [2] 1a 2e [2] 16 24 [2] 01 2f [2] 1a 61 [2] 27 }

  condition:
    any of them
}