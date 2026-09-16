rule TTP_XOR_MULT_DOSStub_1c41 {
  strings:
    $key_1c41 = { 48 29 [2] 3c 31 [2] 7b 33 [2] 3c 22 [2] 72 2e [2] 7e 24 [2] 69 2f [2] 72 61 [2] 4f }

  condition:
    any of them
}