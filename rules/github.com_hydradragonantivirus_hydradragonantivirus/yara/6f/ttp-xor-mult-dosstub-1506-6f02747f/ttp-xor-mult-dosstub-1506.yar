rule TTP_XOR_MULT_DOSStub_1506 {
  strings:
    $key_1506 = { 41 6e [2] 35 76 [2] 72 74 [2] 35 65 [2] 7b 69 [2] 77 63 [2] 60 68 [2] 7b 26 [2] 46 }

  condition:
    any of them
}