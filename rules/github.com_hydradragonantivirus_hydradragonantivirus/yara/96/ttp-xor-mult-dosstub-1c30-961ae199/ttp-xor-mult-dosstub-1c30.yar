rule TTP_XOR_MULT_DOSStub_1c30 {
  strings:
    $key_1c30 = { 48 58 [2] 3c 40 [2] 7b 42 [2] 3c 53 [2] 72 5f [2] 7e 55 [2] 69 5e [2] 72 10 [2] 4f }

  condition:
    any of them
}