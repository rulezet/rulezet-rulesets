rule TTP_XOR_MULT_DOSStub_4b46 {
  strings:
    $key_4b46 = { 1f 2e [2] 6b 36 [2] 2c 34 [2] 6b 25 [2] 25 29 [2] 29 23 [2] 3e 28 [2] 25 66 [2] 18 }

  condition:
    any of them
}