rule TTP_XOR_MULT_DOSStub_3246 {
  strings:
    $key_3246 = { 66 2e [2] 12 36 [2] 55 34 [2] 12 25 [2] 5c 29 [2] 50 23 [2] 47 28 [2] 5c 66 [2] 61 }

  condition:
    any of them
}