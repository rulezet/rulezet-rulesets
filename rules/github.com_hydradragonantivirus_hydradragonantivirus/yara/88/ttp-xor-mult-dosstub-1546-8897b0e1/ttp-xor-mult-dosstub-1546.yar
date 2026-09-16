rule TTP_XOR_MULT_DOSStub_1546 {
  strings:
    $key_1546 = { 41 2e [2] 35 36 [2] 72 34 [2] 35 25 [2] 7b 29 [2] 77 23 [2] 60 28 [2] 7b 66 [2] 46 }

  condition:
    any of them
}