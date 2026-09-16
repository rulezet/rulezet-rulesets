rule TTP_XOR_MULT_DOSStub_5c46 {
  strings:
    $key_5c46 = { 08 2e [2] 7c 36 [2] 3b 34 [2] 7c 25 [2] 32 29 [2] 3e 23 [2] 29 28 [2] 32 66 [2] 0f }

  condition:
    any of them
}