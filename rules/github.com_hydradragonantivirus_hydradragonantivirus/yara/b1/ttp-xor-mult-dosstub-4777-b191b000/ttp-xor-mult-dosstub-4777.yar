rule TTP_XOR_MULT_DOSStub_4777 {
  strings:
    $key_4777 = { 13 1f [2] 67 07 [2] 20 05 [2] 67 14 [2] 29 18 [2] 25 12 [2] 32 19 [2] 29 57 [2] 14 }

  condition:
    any of them
}