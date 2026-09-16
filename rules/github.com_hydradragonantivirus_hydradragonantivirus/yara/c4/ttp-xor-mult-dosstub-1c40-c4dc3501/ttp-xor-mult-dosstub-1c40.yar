rule TTP_XOR_MULT_DOSStub_1c40 {
  strings:
    $key_1c40 = { 48 28 [2] 3c 30 [2] 7b 32 [2] 3c 23 [2] 72 2f [2] 7e 25 [2] 69 2e [2] 72 60 [2] 4f }

  condition:
    any of them
}