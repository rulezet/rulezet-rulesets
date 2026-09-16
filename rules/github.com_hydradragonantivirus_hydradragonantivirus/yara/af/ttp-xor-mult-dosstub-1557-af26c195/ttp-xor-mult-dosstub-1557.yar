rule TTP_XOR_MULT_DOSStub_1557 {
  strings:
    $key_1557 = { 41 3f [2] 35 27 [2] 72 25 [2] 35 34 [2] 7b 38 [2] 77 32 [2] 60 39 [2] 7b 77 [2] 46 }

  condition:
    any of them
}