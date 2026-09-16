rule TTP_XOR_MULT_DOSStub_0046 {
  strings:
    $key_0046 = { 54 2e [2] 20 36 [2] 67 34 [2] 20 25 [2] 6e 29 [2] 62 23 [2] 75 28 [2] 6e 66 [2] 53 }

  condition:
    any of them
}