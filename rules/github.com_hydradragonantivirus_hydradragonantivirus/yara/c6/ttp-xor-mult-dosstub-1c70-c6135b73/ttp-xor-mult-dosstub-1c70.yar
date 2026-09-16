rule TTP_XOR_MULT_DOSStub_1c70 {
  strings:
    $key_1c70 = { 48 18 [2] 3c 00 [2] 7b 02 [2] 3c 13 [2] 72 1f [2] 7e 15 [2] 69 1e [2] 72 50 [2] 4f }

  condition:
    any of them
}