rule TTP_XOR_MULT_DOSStub_4c46 {
  strings:
    $key_4c46 = { 18 2e [2] 6c 36 [2] 2b 34 [2] 6c 25 [2] 22 29 [2] 2e 23 [2] 39 28 [2] 22 66 [2] 1f }

  condition:
    any of them
}