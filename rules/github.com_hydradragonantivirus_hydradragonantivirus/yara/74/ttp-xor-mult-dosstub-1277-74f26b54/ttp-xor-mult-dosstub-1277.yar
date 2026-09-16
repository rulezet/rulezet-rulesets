rule TTP_XOR_MULT_DOSStub_1277 {
  strings:
    $key_1277 = { 46 1f [2] 32 07 [2] 75 05 [2] 32 14 [2] 7c 18 [2] 70 12 [2] 67 19 [2] 7c 57 [2] 41 }

  condition:
    any of them
}