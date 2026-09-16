rule TTP_XOR_MULT_DOSStub_1846 {
  strings:
    $key_1846 = { 4c 2e [2] 38 36 [2] 7f 34 [2] 38 25 [2] 76 29 [2] 7a 23 [2] 6d 28 [2] 76 66 [2] 4b }

  condition:
    any of them
}