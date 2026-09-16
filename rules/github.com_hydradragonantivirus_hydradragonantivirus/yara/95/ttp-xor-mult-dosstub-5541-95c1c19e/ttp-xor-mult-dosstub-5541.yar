rule TTP_XOR_MULT_DOSStub_5541 {
  strings:
    $key_5541 = { 01 29 [2] 75 31 [2] 32 33 [2] 75 22 [2] 3b 2e [2] 37 24 [2] 20 2f [2] 3b 61 [2] 06 }

  condition:
    any of them
}