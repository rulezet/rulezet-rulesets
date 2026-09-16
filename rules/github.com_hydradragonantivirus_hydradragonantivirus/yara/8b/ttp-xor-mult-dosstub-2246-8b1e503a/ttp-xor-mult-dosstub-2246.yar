rule TTP_XOR_MULT_DOSStub_2246 {
  strings:
    $key_2246 = { 76 2e [2] 02 36 [2] 45 34 [2] 02 25 [2] 4c 29 [2] 40 23 [2] 57 28 [2] 4c 66 [2] 71 }

  condition:
    any of them
}