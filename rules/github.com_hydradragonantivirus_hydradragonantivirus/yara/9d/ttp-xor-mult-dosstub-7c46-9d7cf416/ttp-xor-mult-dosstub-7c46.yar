rule TTP_XOR_MULT_DOSStub_7c46 {
  strings:
    $key_7c46 = { 28 2e [2] 5c 36 [2] 1b 34 [2] 5c 25 [2] 12 29 [2] 1e 23 [2] 09 28 [2] 12 66 [2] 2f }

  condition:
    any of them
}