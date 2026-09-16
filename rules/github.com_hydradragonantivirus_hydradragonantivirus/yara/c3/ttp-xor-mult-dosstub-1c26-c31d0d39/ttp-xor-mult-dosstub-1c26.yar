rule TTP_XOR_MULT_DOSStub_1c26 {
  strings:
    $key_1c26 = { 48 4e [2] 3c 56 [2] 7b 54 [2] 3c 45 [2] 72 49 [2] 7e 43 [2] 69 48 [2] 72 06 [2] 4f }

  condition:
    any of them
}