rule TTP_XOR_MULT_DOSStub_1c31 {
  strings:
    $key_1c31 = { 48 59 [2] 3c 41 [2] 7b 43 [2] 3c 52 [2] 72 5e [2] 7e 54 [2] 69 5f [2] 72 11 [2] 4f }

  condition:
    any of them
}