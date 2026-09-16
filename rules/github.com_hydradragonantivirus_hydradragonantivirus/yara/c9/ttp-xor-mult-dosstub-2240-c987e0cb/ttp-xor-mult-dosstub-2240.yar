rule TTP_XOR_MULT_DOSStub_2240 {
  strings:
    $key_2240 = { 76 28 [2] 02 30 [2] 45 32 [2] 02 23 [2] 4c 2f [2] 40 25 [2] 57 2e [2] 4c 60 [2] 71 }

  condition:
    any of them
}