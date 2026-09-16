rule TTP_XOR_MULT_DOSStub_5946 {
  strings:
    $key_5946 = { 0d 2e [2] 79 36 [2] 3e 34 [2] 79 25 [2] 37 29 [2] 3b 23 [2] 2c 28 [2] 37 66 [2] 0a }

  condition:
    any of them
}