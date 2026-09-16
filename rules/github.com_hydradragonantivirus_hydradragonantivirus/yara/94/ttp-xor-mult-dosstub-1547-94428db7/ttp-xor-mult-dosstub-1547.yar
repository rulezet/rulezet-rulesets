rule TTP_XOR_MULT_DOSStub_1547 {
  strings:
    $key_1547 = { 41 2f [2] 35 37 [2] 72 35 [2] 35 24 [2] 7b 28 [2] 77 22 [2] 60 29 [2] 7b 67 [2] 46 }

  condition:
    any of them
}