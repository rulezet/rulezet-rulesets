rule TTP_XOR_MULT_DOSStub_1777 {
  strings:
    $key_1777 = { 43 1f [2] 37 07 [2] 70 05 [2] 37 14 [2] 79 18 [2] 75 12 [2] 62 19 [2] 79 57 [2] 44 }

  condition:
    any of them
}