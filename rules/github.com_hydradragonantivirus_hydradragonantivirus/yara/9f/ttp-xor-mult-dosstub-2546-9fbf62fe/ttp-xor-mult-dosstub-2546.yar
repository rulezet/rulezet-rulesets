rule TTP_XOR_MULT_DOSStub_2546 {
  strings:
    $key_2546 = { 71 2e [2] 05 36 [2] 42 34 [2] 05 25 [2] 4b 29 [2] 47 23 [2] 50 28 [2] 4b 66 [2] 76 }

  condition:
    any of them
}