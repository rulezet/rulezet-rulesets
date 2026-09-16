rule TTP_XOR_MULT_DOSStub_1c20 {
  strings:
    $key_1c20 = { 48 48 [2] 3c 50 [2] 7b 52 [2] 3c 43 [2] 72 4f [2] 7e 45 [2] 69 4e [2] 72 00 [2] 4f }

  condition:
    any of them
}