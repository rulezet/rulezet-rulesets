rule TTP_XOR_MULT_DOSStub_5e46 {
  strings:
    $key_5e46 = { 0a 2e [2] 7e 36 [2] 39 34 [2] 7e 25 [2] 30 29 [2] 3c 23 [2] 2b 28 [2] 30 66 [2] 0d }

  condition:
    any of them
}