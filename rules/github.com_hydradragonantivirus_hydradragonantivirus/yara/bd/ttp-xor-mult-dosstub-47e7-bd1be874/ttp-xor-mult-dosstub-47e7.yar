rule TTP_XOR_MULT_DOSStub_47e7 {
  strings:
    $key_47e7 = { 13 8f [2] 67 97 [2] 20 95 [2] 67 84 [2] 29 88 [2] 25 82 [2] 32 89 [2] 29 c7 [2] 14 }

  condition:
    any of them
}