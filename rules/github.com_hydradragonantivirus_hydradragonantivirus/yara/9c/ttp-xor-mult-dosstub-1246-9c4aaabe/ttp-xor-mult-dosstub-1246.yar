rule TTP_XOR_MULT_DOSStub_1246 {
  strings:
    $key_1246 = { 46 2e [2] 32 36 [2] 75 34 [2] 32 25 [2] 7c 29 [2] 70 23 [2] 67 28 [2] 7c 66 [2] 41 }

  condition:
    any of them
}