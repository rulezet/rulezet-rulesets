rule TTP_XOR_MULT_DOSStub_1541 {
  strings:
    $key_1541 = { 41 29 [2] 35 31 [2] 72 33 [2] 35 22 [2] 7b 2e [2] 77 24 [2] 60 2f [2] 7b 61 [2] 46 }

  condition:
    any of them
}