rule TTP_XOR_MULT_DOSStub_1c76 {
  strings:
    $key_1c76 = { 48 1e [2] 3c 06 [2] 7b 04 [2] 3c 15 [2] 72 19 [2] 7e 13 [2] 69 18 [2] 72 56 [2] 4f }

  condition:
    any of them
}