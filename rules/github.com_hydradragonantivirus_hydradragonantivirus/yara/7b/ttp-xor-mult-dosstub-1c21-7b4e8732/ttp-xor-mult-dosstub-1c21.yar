rule TTP_XOR_MULT_DOSStub_1c21 {
  strings:
    $key_1c21 = { 48 49 [2] 3c 51 [2] 7b 53 [2] 3c 42 [2] 72 4e [2] 7e 44 [2] 69 4f [2] 72 01 [2] 4f }

  condition:
    any of them
}