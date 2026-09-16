rule TTP_XOR_MULT_DOSStub_4d46 {
  strings:
    $key_4d46 = { 19 2e [2] 6d 36 [2] 2a 34 [2] 6d 25 [2] 23 29 [2] 2f 23 [2] 38 28 [2] 23 66 [2] 1e }

  condition:
    any of them
}