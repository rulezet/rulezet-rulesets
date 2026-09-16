rule TTP_XOR_MULT_DOSStub_1517 {
  strings:
    $key_1517 = { 41 7f [2] 35 67 [2] 72 65 [2] 35 74 [2] 7b 78 [2] 77 72 [2] 60 79 [2] 7b 37 [2] 46 }

  condition:
    any of them
}