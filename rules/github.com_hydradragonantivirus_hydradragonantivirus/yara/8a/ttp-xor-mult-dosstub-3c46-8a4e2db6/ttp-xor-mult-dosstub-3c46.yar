rule TTP_XOR_MULT_DOSStub_3c46 {
  strings:
    $key_3c46 = { 68 2e [2] 1c 36 [2] 5b 34 [2] 1c 25 [2] 52 29 [2] 5e 23 [2] 49 28 [2] 52 66 [2] 6f }

  condition:
    any of them
}