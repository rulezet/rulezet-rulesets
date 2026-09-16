rule TTP_XOR_MULT_DOSStub_2046 {
  strings:
    $key_2046 = { 74 2e [2] 00 36 [2] 47 34 [2] 00 25 [2] 4e 29 [2] 42 23 [2] 55 28 [2] 4e 66 [2] 73 }

  condition:
    any of them
}