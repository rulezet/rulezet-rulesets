rule TTP_XOR_MULT_DOSStub_0e46 {
  strings:
    $key_0e46 = { 5a 2e [2] 2e 36 [2] 69 34 [2] 2e 25 [2] 60 29 [2] 6c 23 [2] 7b 28 [2] 60 66 [2] 5d }

  condition:
    any of them
}