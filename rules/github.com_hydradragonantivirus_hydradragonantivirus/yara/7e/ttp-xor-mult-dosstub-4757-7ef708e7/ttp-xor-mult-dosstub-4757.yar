rule TTP_XOR_MULT_DOSStub_4757 {
  strings:
    $key_4757 = { 13 3f [2] 67 27 [2] 20 25 [2] 67 34 [2] 29 38 [2] 25 32 [2] 32 39 [2] 29 77 [2] 14 }

  condition:
    any of them
}