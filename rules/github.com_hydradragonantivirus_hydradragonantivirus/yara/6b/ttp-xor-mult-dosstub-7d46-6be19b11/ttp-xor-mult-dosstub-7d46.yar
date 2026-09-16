rule TTP_XOR_MULT_DOSStub_7d46 {
  strings:
    $key_7d46 = { 29 2e [2] 5d 36 [2] 1a 34 [2] 5d 25 [2] 13 29 [2] 1f 23 [2] 08 28 [2] 13 66 [2] 2e }

  condition:
    any of them
}