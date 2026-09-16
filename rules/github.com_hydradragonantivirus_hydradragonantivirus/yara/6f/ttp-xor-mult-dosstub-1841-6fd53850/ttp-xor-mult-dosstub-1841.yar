rule TTP_XOR_MULT_DOSStub_1841 {
  strings:
    $key_1841 = { 4c 29 [2] 38 31 [2] 7f 33 [2] 38 22 [2] 76 2e [2] 7a 24 [2] 6d 2f [2] 76 61 [2] 4b }

  condition:
    any of them
}